package scoring

// ModifierKind is the enumeration of supported modifier actions in M2.
type ModifierKind string

const (
	// ModifierKindDelta adds Value to the running score (can be negative).
	ModifierKindDelta ModifierKind = "delta"
	// ModifierKindSetScore replaces the running score with Value. Subsequent
	// deltas apply on top of the replacement; a later set_score replaces again.
	ModifierKindSetScore ModifierKind = "set_score"
)

// Modifier is a single scoring rule: one condition + one action.
type Modifier struct {
	// Name identifies this modifier in the audit trail (Score.Applied).
	Name string
	// Priority determines evaluation order: higher priority runs first.
	// Ties break on YAML declaration order (ASC).
	Priority int
	// Kind is delta or set_score.
	Kind ModifierKind
	// Value is the numeric operand. For delta this is added (can be negative);
	// for set_score this replaces the running score.
	Value int
	// Condition is the precompiled DSL leaf. Never nil after loader validation.
	Condition Condition
}

// Scorer is a named bundle of modifiers keyed to a set of rule IDs. The
// engine dispatches first-match-wins: the first scorer whose RuleIDs contains
// finding.RuleID is used.
type Scorer struct {
	Name      string
	RuleIDs   []string
	Modifiers []Modifier // in declaration order (YAML-ASC for tie-breaking)
}

// canScore returns true if this scorer targets the given rule ID.
func (s *Scorer) canScore(ruleID string) bool {
	for _, id := range s.RuleIDs {
		if id == ruleID {
			return true
		}
	}
	return false
}
