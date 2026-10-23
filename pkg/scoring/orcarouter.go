package scoring

// OrcaRouter Cyber Inference scorers.
//
// OrcaRouter is an OpenAI-compatible AI gateway used by security teams: a
// single bearer key (sk-orca-…) routes to many upstream model providers and to
// the gateway's OrcaCyber models. When Titus finds such a key, the useful
// blast-radius questions are all answered by one unauthenticated-for-free
// call: GET https://api.orcarouter.ai/v1/models returns the catalog the key is
// entitled to call. The response is the provider's own capability declaration,
// so nothing here is inferred from a model's name except the OrcaCyber tier,
// which OrcaRouter marks with an "orcacyber-" id prefix.
//
// All modifiers issue the SAME request. A per-scorer probe cache (see
// orcaRouterProbeCache) makes that literal: the first modifier of a finding
// performs the call and the remaining three read the cached result.
//
// Ref: https://www.orcarouter.ai/docs
// Ref: https://www.orcarouter.ai/models?tier=cyber

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

const (
	// orcaRouterRuleID is the detection rule this scorer is registered for.
	orcaRouterRuleID = "kingfisher.orcarouter.1"

	// orcaRouterModelsURL is the provider's own model catalog. Model discovery
	// and inference share the api.orcarouter.ai origin; the marketing/consent
	// site (www.orcarouter.ai) is a different host and is never called here.
	orcaRouterModelsURL = "https://api.orcarouter.ai/v1/models"

	// Bounds on the catalog response. A catalog is metadata, not content: it
	// must never be able to consume unbounded memory or stall a scan.
	orcaRouterMaxCatalogBytes = 2 << 20 // 2 MiB
	orcaRouterMaxModels       = 2000

	// orcaRouterProbeTTL bounds how long a catalog probe is reused inside a
	// long-lived process (titus serve). Scans are short-lived, so this mostly
	// keeps the cache honest rather than saving requests.
	orcaRouterProbeTTL = 5 * time.Minute

	// orcaRouterProbeCacheMax bounds the probe cache so a scan with many
	// distinct keys cannot grow it without limit.
	orcaRouterProbeCacheMax = 256

	// orcaRouterCyberIDPrefix marks the gateway's cyber-tier model family
	// (OrcaCyber Ultra / Zero). Those models are gated behind business
	// verification, so a key that can reach them is worth more to an attacker.
	orcaRouterCyberIDPrefix = "orcacyber-"
)

// orcaRouterChatEndpointTypes are the endpoint types that make a catalog entry
// usable for chat/agent work. An entry that declares none of them — or does not
// declare supported_endpoint_types at all — is excluded: capability is never
// inferred from a model name, so unknown entries fail closed.
var orcaRouterChatEndpointTypes = map[string]bool{
	"openai":          true,
	"anthropic":       true,
	"gemini":          true,
	"openai-response": true,
}

// orcaRouterModel is the subset of a catalog entry this scorer relies on.
type orcaRouterModel struct {
	ID                     string                  `json:"id"`
	SupportedEndpointTypes []string                `json:"supported_endpoint_types"`
	Architecture           *orcaRouterArchitecture `json:"architecture"`
}

// orcaRouterArchitecture is the modality block of a catalog entry.
type orcaRouterArchitecture struct {
	InputModalities  []string `json:"input_modalities"`
	OutputModalities []string `json:"output_modalities"`
}

// orcaRouterCatalog is the capability summary derived from GET /v1/models.
type orcaRouterCatalog struct {
	// ChatModels counts entries that explicitly declare a chat-capable
	// endpoint type.
	ChatModels int
	// CyberModels counts chat-capable entries in the OrcaCyber tier.
	CyberModels int
	// MultimodalModels counts chat-capable entries that accept a non-text
	// input modality (image, audio, or video).
	MultimodalModels int
	// TotalModels counts every entry the catalog returned, chat-capable or not.
	TotalModels int
}

// isChatCapable reports whether a catalog entry explicitly declares a
// chat-capable endpoint type.
func isChatCapable(m orcaRouterModel) bool {
	for _, t := range m.SupportedEndpointTypes {
		if orcaRouterChatEndpointTypes[strings.ToLower(strings.TrimSpace(t))] {
			return true
		}
	}
	return false
}

// isCyberTier reports whether a catalog entry belongs to the OrcaCyber family.
func isCyberTier(m orcaRouterModel) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(m.ID)), orcaRouterCyberIDPrefix)
}

// isMultimodal reports whether a catalog entry accepts a non-text input
// modality. Entries that declare no modalities are treated as text-only.
func isMultimodal(m orcaRouterModel) bool {
	if m.Architecture == nil {
		return false
	}
	for _, mod := range m.Architecture.InputModalities {
		switch strings.ToLower(strings.TrimSpace(mod)) {
		case "image", "audio", "video":
			return true
		}
	}
	return false
}

// summarizeOrcaRouterCatalog turns raw catalog entries into the counts the
// scorers need. Entries with an empty id are ignored (they cannot be addressed
// by a client), and the input is capped at orcaRouterMaxModels.
func summarizeOrcaRouterCatalog(models []orcaRouterModel) orcaRouterCatalog {
	var out orcaRouterCatalog
	for i, m := range models {
		if i >= orcaRouterMaxModels {
			break
		}
		if strings.TrimSpace(m.ID) == "" {
			continue
		}
		out.TotalModels++
		if !isChatCapable(m) {
			continue
		}
		out.ChatModels++
		if isCyberTier(m) {
			out.CyberModels++
		}
		if isMultimodal(m) {
			out.MultimodalModels++
		}
	}
	return out
}

// parseOrcaRouterCatalog accepts both the OpenAI-compatible envelope
// ({"data":[...]}) and a bare array, which is what some gateways return.
func parseOrcaRouterCatalog(body []byte) ([]orcaRouterModel, error) {
	var envelope struct {
		Data []orcaRouterModel `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Data != nil {
		return envelope.Data, nil
	}
	var bare []orcaRouterModel
	if err := json.Unmarshal(body, &bare); err == nil {
		return bare, nil
	}
	return nil, fmt.Errorf("%w: model catalog is not valid JSON", ErrModifierParseError)
}

// -----------------------------------------------------------------------------
// Probe: one authenticated catalog request, cached per key
// -----------------------------------------------------------------------------

// orcaRouterProbe is the classified result of GET /v1/models for one key.
type orcaRouterProbe struct {
	status  int
	catalog orcaRouterCatalog
	expires time.Time
}

// orcaRouterProbeCache memoizes catalog probes by key fingerprint so the four
// modifiers of a finding share one network call. Keys are fingerprinted, never
// stored raw, and the map is bounded.
type orcaRouterProbeCache struct {
	mu      sync.Mutex
	entries map[string]*orcaRouterProbe
}

func newOrcaRouterProbeCache() *orcaRouterProbeCache {
	return &orcaRouterProbeCache{entries: make(map[string]*orcaRouterProbe)}
}

func (c *orcaRouterProbeCache) get(fingerprint string) (*orcaRouterProbe, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.entries[fingerprint]
	if !ok || time.Now().After(p.expires) {
		return nil, false
	}
	return p, true
}

func (c *orcaRouterProbeCache) put(fingerprint string, p *orcaRouterProbe) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= orcaRouterProbeCacheMax {
		// Bounded memory matters more than the hit rate on a huge scan.
		c.entries = make(map[string]*orcaRouterProbe)
	}
	c.entries[fingerprint] = p
}

func orcaRouterFingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// orcaRouterProbeMode selects which catalog fact a modifier asks for.
type orcaRouterProbeMode int

const (
	orcaRouterProbeRevoked orcaRouterProbeMode = iota
	orcaRouterProbeBroad
	orcaRouterProbeLimited
	orcaRouterProbeCyber
)

// orcaRouterHTTPClient is the subset of *http.Client used here (test seam).
type orcaRouterHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// orcaRouterCatalogCondition is a dynamic Condition backed by GET /v1/models.
type orcaRouterCatalogCondition struct {
	mode   orcaRouterProbeMode
	client orcaRouterHTTPClient
	url    string
	cache  *orcaRouterProbeCache
}

// markDynamic gates the condition behind --score-scope, like every other
// network-backed modifier.
func (c *orcaRouterCatalogCondition) markDynamic() {}

// Evaluate implements Condition.
func (c *orcaRouterCatalogCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	key, ok := extractOrcaRouterKey(m)
	if !ok {
		return false, nil
	}

	probe, err := c.probe(ctx, key)
	if err != nil {
		return false, err
	}

	switch c.mode {
	case orcaRouterProbeRevoked:
		return probe.status == http.StatusUnauthorized || probe.status == http.StatusForbidden, nil
	case orcaRouterProbeBroad:
		return probe.status == http.StatusOK && probe.catalog.ChatModels >= 10, nil
	case orcaRouterProbeLimited:
		return probe.status == http.StatusOK && probe.catalog.ChatModels > 0 && probe.catalog.ChatModels < 10, nil
	case orcaRouterProbeCyber:
		return probe.status == http.StatusOK && probe.catalog.CyberModels > 0, nil
	default:
		return false, nil
	}
}

// probe returns the (possibly cached) catalog probe for key.
func (c *orcaRouterCatalogCondition) probe(ctx context.Context, key string) (*orcaRouterProbe, error) {
	fingerprint := orcaRouterFingerprint(key)
	if c.cache != nil {
		if p, ok := c.cache.get(fingerprint); ok {
			return p, nil
		}
	}

	p, err := c.fetch(ctx, key)
	if err != nil {
		// Transient failures are not cached: the next finding gets a fresh try.
		return nil, err
	}
	if c.cache != nil {
		p.expires = time.Now().Add(orcaRouterProbeTTL)
		c.cache.put(fingerprint, p)
	}
	return p, nil
}

func (c *orcaRouterCatalogCondition) modelsURL() string {
	if c.url != "" {
		return c.url
	}
	return orcaRouterModelsURL
}

func (c *orcaRouterCatalogCondition) httpClient() orcaRouterHTTPClient {
	if c.client != nil {
		return c.client
	}
	return http.DefaultClient
}

// fetch performs the catalog request and classifies the response. Error
// messages never contain the key or the response body.
func (c *orcaRouterCatalogCondition) fetch(ctx context.Context, key string) (*orcaRouterProbe, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.modelsURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrModifierNetwork, err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrModifierNetwork, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, orcaRouterMaxCatalogBytes+1))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrModifierNetwork, err)
		}
		if len(body) > orcaRouterMaxCatalogBytes {
			return nil, fmt.Errorf("%w: model catalog exceeds %d bytes", ErrModifierParseError, orcaRouterMaxCatalogBytes)
		}
		models, err := parseOrcaRouterCatalog(body)
		if err != nil {
			return nil, err
		}
		return &orcaRouterProbe{status: resp.StatusCode, catalog: summarizeOrcaRouterCatalog(models)}, nil

	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// Revoked or invalid key: a terminal classification, not an error.
		return &orcaRouterProbe{status: resp.StatusCode}, nil

	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, classifyHTTPError(resp.StatusCode, nil)

	default:
		// Anything else (404 on a moved endpoint, 3xx) means this condition
		// cannot classify the credential; say so without failing the scan.
		return nil, fmt.Errorf("%w: unexpected status %d from model catalog", ErrConditionNotApplicable, resp.StatusCode)
	}
}

// extractOrcaRouterKey reads the key from the rule's named capture group,
// falling back to the first positional group.
func extractOrcaRouterKey(m *types.Match) (string, bool) {
	if m == nil {
		return "", false
	}
	if v, ok := m.NamedGroups["key"]; ok && len(v) > 0 {
		return string(v), true
	}
	if len(m.Groups) > 0 && len(m.Groups[0]) > 0 {
		return string(m.Groups[0]), true
	}
	return "", false
}

// OrcaRouterGoScorer returns the built-in scorer for OrcaRouter Cyber
// Inference API keys (kingfisher.orcarouter.1).
//
// Dynamic modifiers only (--score-scope required). Priorities are ordered so a
// dead credential is scored last, matching the other provider scorers.
func OrcaRouterGoScorer() *Scorer {
	return newOrcaRouterScorer(nil, "")
}

// newOrcaRouterScorer builds the scorer with an optional client/URL override.
// Production passes nil/"" so requests go to the real provider; tests point it
// at an httptest server. Both paths share the same classification code.
func newOrcaRouterScorer(client orcaRouterHTTPClient, url string) *Scorer {
	cache := newOrcaRouterProbeCache()
	condition := func(mode orcaRouterProbeMode) Condition {
		return &orcaRouterCatalogCondition{mode: mode, cache: cache, client: client, url: url}
	}

	return &Scorer{
		Name:    "orcarouter-key-scope",
		RuleIDs: []string{orcaRouterRuleID},
		Modifiers: []Modifier{
			// Cyber-tier reach: the key can drive OrcaCyber Ultra / Zero, which
			// OrcaRouter only unlocks for business-verified security teams.
			{Name: "cyber-model-access", Priority: 95, Kind: ModifierKindDelta, Value: 10, Condition: condition(orcaRouterProbeCyber)},
			// Broad catalog access: paid-tier key with many routable models.
			{Name: "broad-model-access", Priority: 90, Kind: ModifierKindDelta, Value: 10, Condition: condition(orcaRouterProbeBroad)},
			// Narrow access: a key that can reach few or no chat models is a
			// lower-value credential.
			{Name: "limited-model-access", Priority: 80, Kind: ModifierKindDelta, Value: -15, Condition: condition(orcaRouterProbeLimited)},
			// Dead credential: revoked or invalid.
			{Name: "revoked-key", Priority: 10, Kind: ModifierKindSetScore, Value: 5, Condition: condition(orcaRouterProbeRevoked)},
		},
	}
}
