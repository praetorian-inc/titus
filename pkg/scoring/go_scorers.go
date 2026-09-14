package scoring

import "github.com/praetorian-inc/titus/pkg/llm"

// BuiltinGoScorers returns the set of custom Go scorers registered for M4.
// Prepended to YAML scorers so they take first-match-wins precedence.
func BuiltinGoScorers() []*Scorer {
	return []*Scorer{
		AWSGoScorer(),
		GitHubGoScorer(),
		GitHubClassicPATGoScorer(),
		PubNubGoScorer(),
		SupabaseGoScorer(),
		AtlassianGoScorer(),
		MongoDBGoScorer(),
		MongoDBAtlasGoScorer(),
		GitLabGoScorer(),
		GCPGoScorer(),
		AzureGoScorer(),
		PlaidGoScorer(),
		CreditCardGoScorer(),
	}
}

// AllBuiltinScorers returns the complete built-in scorer set: Go scorers first
// (so they take first-match-wins precedence) followed by the built-in YAML
// scorers. Both the CLI (cmd/titus/scan.go) and the library scanner
// (titus.go WithScoring) MUST use this so their scoring behavior stays
// identical — assembling the list in only one path silently drops Go-scored
// rules (e.g. classic GitHub PATs) from the other.
//
// An optional llm.Client is threaded through to every YAML scorer's llm:
// conditions. Omit it (or pass nil) when LLM scoring is unavailable — llm:
// conditions with a nil client silently evaluate to false rather than firing.
func AllBuiltinScorers(llmClient ...llm.Client) ([]*Scorer, error) {
	var client llm.Client
	if len(llmClient) > 0 {
		client = llmClient[0]
	}
	yamlScorers, err := NewLoader().WithLLMClient(client).LoadBuiltinScorers()
	if err != nil {
		return nil, err
	}
	return append(BuiltinGoScorers(), yamlScorers...), nil
}
