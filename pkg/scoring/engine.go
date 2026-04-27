package scoring

import (
	"fmt"
	"os"
	"sort"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Engine applies static modifiers to findings. Construct once per scan.
type Engine struct {
	scorers []*Scorer
	// warnf is pluggable for tests; defaults to stderr logging to match the
	// matcher's warning style (cmd/titus/scan.go:302).
	warnf func(format string, args ...any)
}

// NewEngine constructs an Engine with the given scorers in first-match-wins
// order. Passing nil yields an engine that always returns base-only scores.
func NewEngine(scorers []*Scorer) *Engine {
	return &Engine{
		scorers: scorers,
		warnf:   func(format string, args ...any) { fmt.Fprintf(os.Stderr, format, args...) },
	}
}

// Score computes the finding's score. It never returns an error — condition
// evaluation errors are logged as warnings and the offending modifier is
// skipped. Order of operations:
//
//  1. Find the first scorer whose RuleIDs contains rule.ID (or base-only).
//  2. Sort modifiers by priority DESC, YAML declaration order ASC on ties.
//  3. Evaluate each modifier's condition against the primary match.
//  4. Apply action (delta accumulates, set_score replaces).
//  5. Clamp final to [0, 100], recompute SuggestedSeverity.
//
// Contract: matches must be non-empty when at least one modifier exists;
// callers in runScan always pass the current match.
func (e *Engine) Score(f *types.Finding, matches []*types.Match, rule *types.Rule) *types.Score {
	score := &types.Score{
		Final:             rule.BaseScore,
		Base:              rule.BaseScore,
		SuggestedSeverity: types.SeverityForScore(rule.BaseScore),
		Applied:           []types.ScoreModifier{},
	}
	scorer := e.findScorer(f.RuleID)
	if scorer == nil || len(scorer.Modifiers) == 0 {
		return score
	}
	var primary *types.Match
	if len(matches) > 0 {
		primary = matches[0]
	}
	// Priority DESC, YAML-ASC on ties. Make a stable copy to preserve
	// declaration order for tie-breaking.
	ordered := make([]indexedModifier, len(scorer.Modifiers))
	for i, m := range scorer.Modifiers {
		ordered[i] = indexedModifier{mod: m, yamlIdx: i}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].mod.Priority != ordered[j].mod.Priority {
			return ordered[i].mod.Priority > ordered[j].mod.Priority
		}
		return ordered[i].yamlIdx < ordered[j].yamlIdx
	})

	current := score.Final
	for _, im := range ordered {
		m := im.mod
		fired, err := m.Condition.Evaluate(primary)
		if err != nil {
			e.warnf("[warn] scorer %q modifier %q: %v (skipping)\n", scorer.Name, m.Name, err)
			continue
		}
		if !fired {
			continue
		}
		switch m.Kind {
		case ModifierKindDelta:
			current += m.Value
		case ModifierKindSetScore:
			current = m.Value
		default:
			e.warnf("[warn] scorer %q modifier %q: unknown kind %q (skipping)\n", scorer.Name, m.Name, m.Kind)
			continue
		}
		score.Applied = append(score.Applied, types.ScoreModifier{
			Name:     m.Name,
			Scorer:   scorer.Name,
			Kind:     string(m.Kind),
			Value:    m.Value,
			Priority: m.Priority,
		})
	}

	// Clamp ONCE at the end.
	if current < 0 {
		current = 0
	}
	if current > 100 {
		current = 100
	}
	score.Final = current
	score.SuggestedSeverity = types.SeverityForScore(current)
	return score
}

// findScorer returns the first scorer targeting the given ruleID, or nil.
func (e *Engine) findScorer(ruleID string) *Scorer {
	for _, s := range e.scorers {
		if s.canScore(ruleID) {
			return s
		}
	}
	return nil
}

// indexedModifier pairs a modifier with its original YAML declaration index.
type indexedModifier struct {
	mod     Modifier
	yamlIdx int
}
