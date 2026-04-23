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
