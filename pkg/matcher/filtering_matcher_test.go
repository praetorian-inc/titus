package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func matchRuleIDs(ms []*types.Match) []string {
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.RuleID)
	}
	return ids
}

// A hidden rule that shares a captured value with a visible rule would win the
// cross-rule dedup cluster (non-generic, more groups). Its match must be dropped
// before dedup, so the visible match is the one reported.
func TestHiddenRule_NeverReportedAndNeverDisplacesVisibleMatch(t *testing.T) {
	const token = "Q7xVm2LpZ9rT4kWn8bHc"
	hidden := &types.Rule{
		ID:      "test.helper.1",
		Pattern: `client=(?P<client>[a-z]{4}) key=(?P<token>[A-Za-z0-9]{20})`,
		Hidden:  true,
	}
	visible := &types.Rule{
		ID:         "test.generic.1",
		Pattern:    `key=(?P<token>[A-Za-z0-9]{20})`,
		Categories: []string{"generic"},
	}

	m, err := New(Config{Rules: []*types.Rule{hidden, visible}})
	require.NoError(t, err)
	defer func() { _ = m.Close() }()

	ms, err := m.Match([]byte("client=abcd key=" + token + "\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"test.generic.1"}, matchRuleIDs(ms))
	assert.Equal(t, token, string(ms[0].NamedGroups["token"]))
}

// Every builtin rule marked visible: false matches its own examples (the
// examples guard checks that), yet none of those matches may reach a caller.
func TestHiddenBuiltinRules_ExamplesProduceNoMatches(t *testing.T) {
	all, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)

	var hidden []*types.Rule
	for _, r := range all {
		if r.Hidden {
			hidden = append(hidden, r)
		}
	}
	require.NotEmpty(t, hidden, "no builtin rule loaded as hidden; is visible: false still parsed?")

	for _, r := range hidden {
		m, err := New(Config{Rules: []*types.Rule{r}})
		require.NoErrorf(t, err, "rule %q", r.ID)
		for i, ex := range r.Examples {
			ms, err := m.Match([]byte(ex))
			require.NoErrorf(t, err, "rule %q example %d", r.ID, i)
			assert.Emptyf(t, ms, "hidden rule %q reported a match for examples[%d] %q", r.ID, i, ex)
		}
		require.NoError(t, m.Close())
	}
}
