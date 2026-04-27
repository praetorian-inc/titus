package scoring

import (
	"regexp"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCondition_InterfaceCompliance is a compile-time-ish check that each
// concrete condition satisfies the Condition interface. It will be expanded
// in tasks 0.3-0.5 as each leaf type is implemented.
func TestCondition_InterfaceCompliance(t *testing.T) {
	var _ Condition = (*matchGroupCondition)(nil)
	var _ Condition = (*surroundingContextContainsCondition)(nil)
	var _ Condition = (*matchLengthCondition)(nil)
	// Sanity: zero match must not panic any default nil-safe path.
	m := &types.Match{}
	assert.NotNil(t, m)
}

func TestMatchGroupCondition_Evaluate(t *testing.T) {
	tests := []struct {
		name        string
		groupName   string
		pattern     string
		namedGroups map[string][]byte
		wantFired   bool
		wantErr     bool
	}{
		{
			name:        "AKIA prefix fires on key_id group",
			groupName:   "key_id",
			pattern:     `^AKIA`,
			namedGroups: map[string][]byte{"key_id": []byte("AKIAIOSFODNN7EXAMPLE")},
			wantFired:   true,
		},
		{
			name:        "ASIA prefix does not fire on AKIA regex",
			groupName:   "key_id",
			pattern:     `^AKIA`,
			namedGroups: map[string][]byte{"key_id": []byte("ASIAIOSFODNN7EXAMPLE")},
			wantFired:   false,
		},
		{
			name:        "missing named group is non-fire, not error",
			groupName:   "nonexistent",
			pattern:     `.*`,
			namedGroups: map[string][]byte{"key_id": []byte("AKIA...")},
			wantFired:   false,
		},
		{
			name:        "github_pat_ prefix fires on token group",
			groupName:   "token",
			pattern:     `^github_pat_`,
			namedGroups: map[string][]byte{"token": []byte("github_pat_11ABC...")},
			wantFired:   true,
		},
		{
			name:        "classic ghp_ token does not fire on github_pat_ regex",
			groupName:   "token",
			pattern:     `^github_pat_`,
			namedGroups: map[string][]byte{"token": []byte("ghp_11ABC...")},
			wantFired:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, err := regexp.Compile(tt.pattern)
			require.NoError(t, err)
			c := &matchGroupCondition{Name: tt.groupName, Regex: re}
			m := &types.Match{NamedGroups: tt.namedGroups}
			got, err := c.Evaluate(m)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantFired, got)
		})
	}
}

func TestMatchGroupCondition_NilSafety(t *testing.T) {
	c := &matchGroupCondition{Name: "x", Regex: regexp.MustCompile(`.`)}
	got, err := c.Evaluate(nil)
	require.NoError(t, err)
	assert.False(t, got)

	var nilCond *matchGroupCondition
	_, err = nilCond.Evaluate(&types.Match{})
	require.Error(t, err)
}

func TestSurroundingContextContainsCondition_Evaluate(t *testing.T) {
	mkMatch := func(before, after string) *types.Match {
		return &types.Match{Snippet: types.Snippet{
			Before: []byte(before),
			After:  []byte(after),
		}}
	}
	tests := []struct {
		name      string
		within    int
		value     string
		match     *types.Match
		wantFired bool
	}{
		{
			name:      "found in before (unlimited)",
			within:    0,
			value:     "docker",
			match:     mkMatch("FROM docker:latest\n", "run"),
			wantFired: true,
		},
		{
			name:      "found in after (unlimited)",
			within:    0,
			value:     "example",
			match:     mkMatch("", "this is an example line"),
			wantFired: true,
		},
		{
			name:      "not found anywhere",
			within:    0,
			value:     "kubernetes",
			match:     mkMatch("docker stuff", "and more docker"),
			wantFired: false,
		},
		{
			name:      "within limits prevents match",
			within:    3,
			value:     "docker",
			match:     mkMatch("0123456789docker", ""), // "docker" is 10+ chars away from match
			wantFired: false,
		},
		{
			name:      "within limits preserves close match",
			within:    10,
			value:     "docker",
			match:     mkMatch("docker0123", ""), // within 10 bytes of end
			wantFired: true,
		},
		{
			name:      "nil match is non-fire",
			within:    0,
			value:     "anything",
			match:     nil,
			wantFired: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &surroundingContextContainsCondition{Within: tt.within, Value: tt.value}
			got, err := c.Evaluate(tt.match)
			require.NoError(t, err)
			assert.Equal(t, tt.wantFired, got)
		})
	}
}

func TestSurroundingContextContainsCondition_EmptyValueIsError(t *testing.T) {
	c := &surroundingContextContainsCondition{Within: 0, Value: ""}
	_, err := c.Evaluate(&types.Match{})
	require.Error(t, err)
}

func TestMatchLengthCondition_Evaluate(t *testing.T) {
	mkMatch := func(matching string) *types.Match {
		return &types.Match{Snippet: types.Snippet{Matching: []byte(matching)}}
	}
	tests := []struct {
		name      string
		op        matchLengthOp
		value     int
		match     *types.Match
		wantFired bool
	}{
		{"gt fires when longer", matchLengthOpGT, 10, mkMatch("AKIAIOSFODNN7EXAMPLE"), true},
		{"gt no-fire when shorter", matchLengthOpGT, 50, mkMatch("AKIAIOSFODNN7EXAMPLE"), false},
		{"gt boundary: equal is not greater", matchLengthOpGT, 20, mkMatch("AKIAIOSFODNN7EXAMPLE"), false},
		{"lt fires when shorter", matchLengthOpLT, 30, mkMatch("AKIAIOSFODNN7EXAMPLE"), true},
		{"lt no-fire when longer", matchLengthOpLT, 5, mkMatch("AKIAIOSFODNN7EXAMPLE"), false},
		{"eq fires on exact length", matchLengthOpEQ, 20, mkMatch("AKIAIOSFODNN7EXAMPLE"), true},
		{"eq no-fire when off by one", matchLengthOpEQ, 19, mkMatch("AKIAIOSFODNN7EXAMPLE"), false},
		{"empty matching has length 0", matchLengthOpEQ, 0, mkMatch(""), true},
		{"nil match is non-fire", matchLengthOpGT, 0, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &matchLengthCondition{Op: tt.op, Value: tt.value}
			got, err := c.Evaluate(tt.match)
			require.NoError(t, err)
			assert.Equal(t, tt.wantFired, got)
		})
	}
}

func TestMatchLengthCondition_InvalidOpIsError(t *testing.T) {
	c := &matchLengthCondition{Op: "bogus", Value: 0}
	_, err := c.Evaluate(&types.Match{Snippet: types.Snippet{Matching: []byte("x")}})
	require.Error(t, err)
}
