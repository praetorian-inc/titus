package scoring

import (
	"context"
	"strings"

	"github.com/praetorian-inc/titus/pkg/llm"
	"github.com/praetorian-inc/titus/pkg/types"
)

// llmCondition is a dynamic Condition that asks an LLM to evaluate a match
// against a prompt template and fires when the response contains firesWhen
// (case-insensitively). It implements networkCondition, gating it behind
// --score-scope the same way httpCondition is gated.
type llmCondition struct {
	client        llm.Client
	promptTpl     string
	firesWhen     string
	capturePrompt *string // test hook, nil in production
}

// newLLMCondition constructs an llmCondition.
func newLLMCondition(client llm.Client, promptTpl, firesWhen string) *llmCondition {
	return &llmCondition{
		client:    client,
		promptTpl: promptTpl,
		firesWhen: firesWhen,
	}
}

// markDynamic implements the networkCondition marker interface.
// This gates LLM conditions behind --score-scope.
func (c *llmCondition) markDynamic() {}

// Evaluate renders the prompt template against the match's named groups and
// rule ID, sends it to the LLM, and fires when the response contains
// firesWhen (case-insensitively). Errors from the LLM call silently return
// false (condition does not fire) rather than propagating, since a transient
// LLM failure should not be treated as a scoring engine error.
func (c *llmCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	if m == nil {
		return false, nil
	}

	prompt := substituteMatchVars(c.promptTpl, m)
	if c.capturePrompt != nil {
		*c.capturePrompt = prompt
	}

	resp, err := c.client.Complete(ctx, &llm.Request{
		System:    "You are analyzing a detected secret. Answer concisely.",
		Messages:  []llm.Message{{Role: "user", Content: prompt}},
		MaxTokens: 256,
	})
	if err != nil {
		return false, nil
	}

	return strings.Contains(strings.ToLower(resp.Content), strings.ToLower(c.firesWhen)), nil
}

// substituteMatchVars replaces {{name}} and {{ name }} placeholders in tpl
// with values drawn from the match: rule_name (RuleID), matching
// (Snippet.Matching), and each entry in NamedGroups. Untrusted match data is
// substituted verbatim here; callers constructing prompts from untrusted
// sources should sanitize via llm.Sanitize/llm.WrapUntrusted beforehand.
func substituteMatchVars(tpl string, m *types.Match) string {
	tpl = strings.ReplaceAll(tpl, "{{rule_name}}", m.RuleID)
	tpl = strings.ReplaceAll(tpl, "{{ rule_name }}", m.RuleID)
	for name, value := range m.NamedGroups {
		val := string(value)
		tpl = strings.ReplaceAll(tpl, "{{"+name+"}}", val)
		tpl = strings.ReplaceAll(tpl, "{{ "+name+" }}", val)
	}
	if m.Snippet.Matching != nil {
		val := string(m.Snippet.Matching)
		tpl = strings.ReplaceAll(tpl, "{{matching}}", val)
		tpl = strings.ReplaceAll(tpl, "{{ matching }}", val)
	}
	return tpl
}
