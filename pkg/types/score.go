package types

// Score captures a finding's computed severity score and the modifiers that
// produced it. Score values are integers in [0, 100] where 0 is minimal
// severity and 100 is maximum severity.
type Score struct {
	// Final is the clamped 0-100 score after all modifiers are applied.
	Final int
	// Base is the rule's BaseScore before any modifiers.
	Base int
	// SuggestedSeverity is a tier hint derived from Final. Downstream
	// consumers (Chariot, SARIF) may remap these bands.
	// Values: "info" (0-19), "low" (20-39), "medium" (40-59),
	//         "high" (60-79), "critical" (80-100).
	SuggestedSeverity string
	// Applied is the audit trail of modifiers that fired, in evaluation order.
	// For Milestone 1 this is always empty (no engine yet) — the engine lands
	// in Milestones 2+.
	Applied []ScoreModifier
}

// ScoreModifier records a single modifier that fired during scoring.
type ScoreModifier struct {
	Name     string
	Scorer   string
	Kind     string // "delta" or "set_score"
	Value    int
	Priority int
}

// SeverityForScore maps a numeric score to its suggested severity tier.
// Out-of-range inputs are clamped (below 0 → info, above 100 → critical).
func SeverityForScore(score int) string {
	switch {
	case score < 20:
		return "info"
	case score < 40:
		return "low"
	case score < 60:
		return "medium"
	case score < 80:
		return "high"
	default:
		return "critical"
	}
}
