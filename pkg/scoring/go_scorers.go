package scoring

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
	}
}

// AllBuiltinScorers returns the complete built-in scorer set: Go scorers first
// (so they take first-match-wins precedence) followed by the built-in YAML
// scorers. Both the CLI (cmd/titus/scan.go) and the library scanner
// (titus.go WithScoring) MUST use this so their scoring behavior stays
// identical — assembling the list in only one path silently drops Go-scored
// rules (e.g. classic GitHub PATs) from the other.
func AllBuiltinScorers() ([]*Scorer, error) {
	yamlScorers, err := NewLoader().LoadBuiltinScorers()
	if err != nil {
		return nil, err
	}
	return append(BuiltinGoScorers(), yamlScorers...), nil
}
