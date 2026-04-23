package scoring

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Condition is the v1 static-DSL leaf interface. Implementations inspect a
// single *types.Match (the primary/first match for a finding) and return
// whether the condition fires.
//
// M2 has three concrete implementations. Compound conditions (all/any/not)
// and HTTP conditions are out of scope (M3+).
type Condition interface {
	// Evaluate returns (fired, err). On err != nil, the caller (engine)
	// logs a warning and treats the modifier as not-fired for this finding.
	// Evaluate must never panic; inputs are trusted (post-loader).
	Evaluate(m *types.Match) (bool, error)
}

// -----------------------------------------------------------------------------
// match_group: regex match against a named capture group
// -----------------------------------------------------------------------------

// matchGroupCondition fires when Match.NamedGroups[Name] matches Regex.
// The regex is compiled at load time — see (*ScorerLoader).loadConditions
// (phase 1).
type matchGroupCondition struct {
	Name  string         // the regex capture group to inspect
	Regex *regexp.Regexp // precompiled; never nil after successful load
}

// Evaluate implements Condition.
func (c *matchGroupCondition) Evaluate(m *types.Match) (bool, error) {
	if c == nil || c.Regex == nil {
		return false, fmt.Errorf("match_group: nil condition or regex")
	}
	if m == nil {
		return false, nil
	}
	val, ok := m.NamedGroups[c.Name]
	if !ok {
		// Group not present is a NON-FIRE, not an error. Many rules share a
		// scorer; not every rule has the named group the scorer cares about.
		return false, nil
	}
	return c.Regex.Match(val), nil
}

// -----------------------------------------------------------------------------
// surrounding_context_contains: substring test on Snippet.Before/After
// -----------------------------------------------------------------------------

// surroundingContextContainsCondition fires when the Value string appears
// within Within bytes of either side of the match. Within=0 means unlimited
// (full Snippet.Before + Snippet.After considered).
type surroundingContextContainsCondition struct {
	Within int    // bytes on each side to inspect; 0 = unlimited
	Value  string // substring to search for
}

// Evaluate implements Condition.
func (c *surroundingContextContainsCondition) Evaluate(m *types.Match) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("surrounding_context_contains: nil condition")
	}
	if c.Value == "" {
		return false, fmt.Errorf("surrounding_context_contains: empty value (caught at load time)")
	}
	if m == nil {
		return false, nil
	}
	before := m.Snippet.Before
	after := m.Snippet.After
	if c.Within > 0 {
		if len(before) > c.Within {
			before = before[len(before)-c.Within:]
		}
		if len(after) > c.Within {
			after = after[:c.Within]
		}
	}
	if strings.Contains(string(before), c.Value) {
		return true, nil
	}
	if strings.Contains(string(after), c.Value) {
		return true, nil
	}
	return false, nil
}

// -----------------------------------------------------------------------------
// match_length: integer comparison on len(Snippet.Matching)
// -----------------------------------------------------------------------------

// matchLengthOp is one of gt|lt|eq. Any other value is rejected at load.
type matchLengthOp string

const (
	matchLengthOpGT matchLengthOp = "gt"
	matchLengthOpLT matchLengthOp = "lt"
	matchLengthOpEQ matchLengthOp = "eq"
)

// matchLengthCondition fires when len(Snippet.Matching) <op> Value.
type matchLengthCondition struct {
	Op    matchLengthOp
	Value int
}

// Evaluate implements Condition.
func (c *matchLengthCondition) Evaluate(m *types.Match) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("match_length: nil condition")
	}
	if m == nil {
		return false, nil
	}
	got := len(m.Snippet.Matching)
	switch c.Op {
	case matchLengthOpGT:
		return got > c.Value, nil
	case matchLengthOpLT:
		return got < c.Value, nil
	case matchLengthOpEQ:
		return got == c.Value, nil
	default:
		return false, fmt.Errorf("match_length: invalid op %q (caught at load time)", c.Op)
	}
}
