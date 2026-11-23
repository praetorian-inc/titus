package rule

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stripeKeyBody returns n alphanumeric characters shaped like a Stripe key
// body. Keys are built here rather than written out so the test file does
// not carry anything that looks like a real credential.
func stripeKeyBody(n int) string {
	const alphabet = "51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[(i*7)%len(alphabet)])
	}
	return b.String()
}

// TestStripeRules_KeyLength checks that np.stripe.1 and np.stripe.2 report
// the whole key for both the 24-character keys issued before 2019 and the
// longer keys Stripe issues now (up to 255 characters in total).
func TestStripeRules_KeyLength(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	byID := map[string]*types.Rule{}
	for _, r := range rules {
		if r.ID == "np.stripe.1" || r.ID == "np.stripe.2" {
			byID[r.ID] = r
		}
	}
	require.Len(t, byID, 2, "np.stripe.1 and np.stripe.2 should exist")

	testCases := []struct {
		name    string
		ruleID  string
		prefix  string
		bodyLen int
		want    bool
	}{
		{name: "legacy live secret key", ruleID: "np.stripe.1", prefix: "sk_live_", bodyLen: 24, want: true},
		{name: "current live secret key", ruleID: "np.stripe.1", prefix: "sk_live_", bodyLen: 99, want: true},
		{name: "current live restricted key", ruleID: "np.stripe.1", prefix: "rk_live_", bodyLen: 99, want: true},
		{name: "longest live key", ruleID: "np.stripe.1", prefix: "sk_live_", bodyLen: 247, want: true},
		{name: "live key too short", ruleID: "np.stripe.1", prefix: "sk_live_", bodyLen: 23, want: false},
		{name: "live key longer than 255 characters", ruleID: "np.stripe.1", prefix: "sk_live_", bodyLen: 248, want: false},
		{name: "legacy test secret key", ruleID: "np.stripe.2", prefix: "sk_test_", bodyLen: 24, want: true},
		{name: "current test secret key", ruleID: "np.stripe.2", prefix: "sk_test_", bodyLen: 99, want: true},
		{name: "current test restricted key", ruleID: "np.stripe.2", prefix: "rk_test_", bodyLen: 99, want: true},
		{name: "test key too short", ruleID: "np.stripe.2", prefix: "sk_test_", bodyLen: 23, want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := matcher.NewPortableRegexp([]*types.Rule{byID[tc.ruleID]}, 0, nil)
			require.NoError(t, err)

			key := tc.prefix + stripeKeyBody(tc.bodyLen)
			matches, err := m.Match([]byte(`STRIPE_SECRET_KEY="` + key + `"`))
			require.NoError(t, err)

			if !tc.want {
				assert.Empty(t, matches)
				return
			}
			require.Len(t, matches, 1)
			assert.Equal(t, key, string(matches[0].NamedGroups["key"]), "the whole key should be reported")
		})
	}
}
