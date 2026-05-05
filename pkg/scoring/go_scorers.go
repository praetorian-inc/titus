package scoring

// BuiltinGoScorers returns the set of custom Go scorers registered for M4.
// Prepended to YAML scorers so they take first-match-wins precedence.
func BuiltinGoScorers() []*Scorer {
	return []*Scorer{
		// AWSGoScorer(),    // Phase 1
		// GitHubGoScorer(), // Phase 2
	}
}
