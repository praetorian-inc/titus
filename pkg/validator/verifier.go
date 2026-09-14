// pkg/validator/verifier.go
package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/praetorian-inc/titus/pkg/llm"
	"github.com/praetorian-inc/titus/pkg/types"
)

// LLMVerifier wraps a validator Engine with an LLM second-pass review of
// undetermined results. It calls the LLM only when the engine's result is
// undetermined and carries ResponseMeta (i.e. an HTTP response was captured
// during validation but the validator couldn't confidently classify it), or
// when confidence is otherwise low. It never downgrades a valid/invalid
// verdict produced by the engine, and it enforces a call budget and bounded
// concurrency against the LLM client.
type LLMVerifier struct {
	engine    *Engine
	llm       llm.Client
	cache     *llm.ResponseCache
	maxTokens int
	budget    int64
	spent     atomic.Int64
	sem       chan struct{}
}

// NewLLMVerifier creates an LLMVerifier wrapping engine, using client for
// LLM calls. maxTokens bounds the LLM response size; budget caps the total
// number of LLM calls this verifier will make over its lifetime.
func NewLLMVerifier(engine *Engine, client llm.Client, maxTokens int, budget int64) *LLMVerifier {
	return &LLMVerifier{
		engine:    engine,
		llm:       client,
		cache:     llm.NewResponseCache(),
		maxTokens: maxTokens,
		budget:    budget,
		sem:       make(chan struct{}, 4),
	}
}

// ValidateMatch validates match via the wrapped Engine, then — if the result
// is undetermined with response data available — asks the LLM for a second
// opinion. The LLM can only fill in undetermined verdicts with valid/invalid,
// it can never downgrade an existing valid/invalid verdict.
func (v *LLMVerifier) ValidateMatch(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	result, err := v.engine.ValidateMatch(ctx, match)
	if err != nil {
		return result, err
	}

	if !v.shouldCallLLM(result) {
		return result, nil
	}

	if v.spent.Load() >= v.budget {
		return result, nil
	}

	select {
	case v.sem <- struct{}{}:
		defer func() { <-v.sem }()
	case <-ctx.Done():
		return result, nil
	}

	upgraded := v.tryLLMUpgrade(ctx, match, result)
	return upgraded, nil
}

// shouldCallLLM reports whether the LLM second pass should be invoked for
// result. High-confidence valid/invalid verdicts are trusted as-is.
// Undetermined verdicts are only escalated to the LLM if there is captured
// HTTP response data to reason about.
func (v *LLMVerifier) shouldCallLLM(result *types.ValidationResult) bool {
	if result.Status == types.StatusValid && result.Confidence >= 0.9 {
		return false
	}
	if result.Status == types.StatusInvalid && result.Confidence >= 0.9 {
		return false
	}
	if result.ResponseMeta == nil {
		return false
	}
	return true
}

const verifierSystemPrompt = `You are a credential validation analyst. Given a secret detection result and the HTTP response from validating it, classify the credential as valid, invalid, or undetermined.

Respond with ONLY a JSON object:
{"status": "valid|invalid|undetermined", "confidence": 0.0-1.0, "reason": "one sentence explanation"}

Rules:
- "valid" means the credential grants access to the service
- "invalid" means the credential is rejected or expired
- "undetermined" means you cannot confidently classify it
- Be conservative: when in doubt, say "undetermined"`

// tryLLMUpgrade builds a prompt from match and original, consults the
// response cache, and — on a cache miss — calls the LLM. Any failure
// (transport error or unparseable response) falls back to original.
func (v *LLMVerifier) tryLLMUpgrade(ctx context.Context, match *types.Match, original *types.ValidationResult) *types.ValidationResult {
	userMsg := v.buildUserMessage(match, original)

	key := llm.CacheKey(verifierSystemPrompt, userMsg)
	if cached := v.cache.Get(key); cached != nil {
		return v.applyLLMResponse(cached.Content, original)
	}

	v.spent.Add(1)

	resp, err := v.llm.Complete(ctx, &llm.Request{
		System:    verifierSystemPrompt,
		Messages:  []llm.Message{{Role: "user", Content: userMsg}},
		MaxTokens: v.maxTokens,
	})
	if err != nil {
		return original
	}

	v.cache.Set(key, resp)
	return v.applyLLMResponse(resp.Content, original)
}

// buildUserMessage renders the LLM prompt for a single undetermined result,
// wrapping the untrusted HTTP response body to mitigate prompt injection.
func (v *LLMVerifier) buildUserMessage(match *types.Match, result *types.ValidationResult) string {
	meta := result.ResponseMeta
	bodyStr := llm.TruncateBody(meta.Body, 2048)

	return fmt.Sprintf(`Rule: %s
Validator verdict: %s (confidence: %.1f)
Validator message: %s

HTTP Response:
Status: %d
URL: %s
%s`,
		match.RuleID,
		result.Status, result.Confidence, result.Message,
		meta.StatusCode, meta.URL,
		llm.WrapUntrusted("response_body", bodyStr),
	)
}

// llmVerdict is the expected JSON shape of the LLM's response.
type llmVerdict struct {
	Status     string  `json:"status"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// applyLLMResponse parses content as a llmVerdict and merges it onto
// original. It falls back to original on parse failure, on an
// "undetermined"/unrecognized verdict, or on any attempt to downgrade an
// existing valid/invalid verdict to the opposite status.
func (v *LLMVerifier) applyLLMResponse(content string, original *types.ValidationResult) *types.ValidationResult {
	var verdict llmVerdict
	if err := json.Unmarshal([]byte(content), &verdict); err != nil {
		return original
	}

	newStatus := types.ValidationStatus(verdict.Status)
	switch newStatus {
	case types.StatusValid, types.StatusInvalid:
	case types.StatusUndetermined:
		return original
	default:
		return original
	}

	if original.Status == types.StatusValid && newStatus == types.StatusInvalid {
		return original
	}
	if original.Status == types.StatusInvalid && newStatus == types.StatusValid {
		return original
	}

	return &types.ValidationResult{
		Status:       newStatus,
		Confidence:   verdict.Confidence,
		Message:      fmt.Sprintf("[LLM] %s", verdict.Reason),
		ValidatedAt:  original.ValidatedAt,
		Details:      original.Details,
		ResponseMeta: original.ResponseMeta,
	}
}

// Stats returns a snapshot of this verifier's LLM usage counters.
func (v *LLMVerifier) Stats() LLMStats {
	return LLMStats{
		Requests:  v.spent.Load(),
		CacheHits: v.cache.Hits(),
	}
}

// LLMStats holds atomic-backed usage counters for an LLMVerifier.
type LLMStats struct {
	Requests     int64
	CacheHits    int64
	Upgrades     int64
	Failures     int64
	InputTokens  int64
	OutputTokens int64
}
