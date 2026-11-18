package scoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinUberLLMScorer_SharesOneBalanceRequest(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.uberllm.1")
	assert.Equal(t, "uberllm-key-credit", s.Name)
	require.Len(t, s.Modifiers, 3)

	for _, m := range s.Modifiers {
		cond, ok := m.Condition.(*httpCondition)
		require.Truef(t, ok, "modifier %q should be http-backed", m.Name)
		assert.Equal(t, "https://api.uberllm.dev/v1/balance", cond.url, "modifier %q", m.Name)
		assert.Equal(t, "GET", cond.method, "modifier %q", m.Name)
		assert.Equal(t, "bearer", cond.auth.Type, "modifier %q", m.Name)
		assert.Equal(t, "key", cond.auth.SecretGroup, "modifier %q", m.Name)
	}
}

// Each balance response must fire exactly the modifiers listed for it.
func TestBuiltinUberLLMScorer_FiresOnBalance(t *testing.T) {
	s := builtinScorerFor(t, "kingfisher.uberllm.1")

	cases := []struct {
		name   string
		status int
		body   string
		fires  []string
	}{
		{"funded", 200, `{"object":"balance","balance_usd":12.5,"held_usd":0,"available_usd":12.5}`, []string{"credit-available"}},
		{"cents left", 200, `{"object":"balance","balance_usd":0.03,"held_usd":0,"available_usd":0.03}`, []string{"credit-available"}},
		{"tiny remainder", 200, `{"object":"balance","balance_usd":0.00005,"held_usd":0,"available_usd":0.00005}`, []string{"credit-available"}},
		{"empty", 200, `{"object":"balance","balance_usd":0,"held_usd":0,"available_usd":0}`, []string{"no-credit"}},
		{"all held", 200, `{"object":"balance","balance_usd":1,"held_usd":1,"available_usd":0}`, []string{"no-credit"}},
		{"revoked", 401, `{"error":{"code":"invalid_api_key"}}`, []string{"revoked-key"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			var fired []string
			for _, m := range s.Modifiers {
				cond := *m.Condition.(*httpCondition)
				cond.url = srv.URL + "/v1/balance"
				ok, _ := cond.Evaluate(context.Background(), matchWithGroups(map[string][]byte{"key": []byte("ull_EXAMPLEkeyDoNotUse4mZ9vT2kL8nR3pW6xY1bC5dQ7")}))
				if ok {
					fired = append(fired, m.Name)
				}
			}
			assert.Equal(t, tc.fires, fired)
		})
	}
}
