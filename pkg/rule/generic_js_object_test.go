package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFilterNoisy verifies the helper drops/keeps noisy rules as advertised.
func TestFilterNoisy(t *testing.T) {
	in := []*types.Rule{
		{ID: "np.test.1", Noisy: false},
		{ID: "np.test.2", Noisy: true},
		{ID: "np.test.3", Noisy: false},
	}

	off := FilterNoisy(in, false)
	assert.Len(t, off, 2)
	for _, r := range off {
		assert.False(t, r.Noisy, "noisy rule %s leaked through", r.ID)
	}

	on := FilterNoisy(in, true)
	assert.Equal(t, in, on, "FilterNoisy(_, true) should return input unchanged")
}

// findRule returns the rule with the given ID, or nil.
func findRule(rules []*types.Rule, id string) *types.Rule {
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// TestGenericJSObjectRules_NoisyOptIn verifies np.generic.17 and np.generic.18
// are loaded as noisy rules and excluded by FilterNoisy unless includeNoisy is true.
func TestGenericJSObjectRules_NoisyOptIn(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	r17 := findRule(rules, "np.generic.17")
	r18 := findRule(rules, "np.generic.18")
	require.NotNil(t, r17, "np.generic.17 should be present in builtin rules")
	require.NotNil(t, r18, "np.generic.18 should be present in builtin rules")

	assert.True(t, r17.Noisy, "np.generic.17 should be marked noisy")
	assert.True(t, r18.Noisy, "np.generic.18 should be marked noisy")

	// FilterNoisy(false) drops both.
	off := FilterNoisy(rules, false)
	assert.Nil(t, findRule(off, "np.generic.17"), "np.generic.17 must be absent when includeNoisy=false")
	assert.Nil(t, findRule(off, "np.generic.18"), "np.generic.18 must be absent when includeNoisy=false")

	// FilterNoisy(true) keeps both.
	on := FilterNoisy(rules, true)
	assert.NotNil(t, findRule(on, "np.generic.17"), "np.generic.17 must be present when includeNoisy=true")
	assert.NotNil(t, findRule(on, "np.generic.18"), "np.generic.18 must be present when includeNoisy=true")
}

// TestGenericJSObjectRules_PatternsMatchExamples runs each rule's positive
// examples (must match) and negative_examples (must not match) through the
// matcher used at scan time.
func TestGenericJSObjectRules_PatternsMatchExamples(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	for _, id := range []string{"np.generic.17", "np.generic.18"} {
		r := findRule(rules, id)
		require.NotNil(t, r, "%s should exist", id)
		require.NotEmpty(t, r.Examples, "%s should have examples", id)
		require.NotEmpty(t, r.NegativeExamples, "%s should have negative_examples", id)

		m, err := matcher.NewPortableRegexp([]*types.Rule{r}, 0, nil)
		require.NoError(t, err, "%s should compile", id)

		for _, ex := range r.Examples {
			ex := ex
			t.Run(id+"/positive/"+ex, func(t *testing.T) {
				matches, err := m.Match([]byte(ex))
				require.NoError(t, err)
				assert.NotEmpty(t, matches, "expected %s to match positive example: %s", id, ex)
			})
		}

		for _, ex := range r.NegativeExamples {
			ex := ex
			t.Run(id+"/negative/"+ex, func(t *testing.T) {
				matches, err := m.Match([]byte(ex))
				require.NoError(t, err)
				assert.Empty(t, matches, "expected %s to NOT match negative example: %s", id, ex)
			})
		}
	}
}
