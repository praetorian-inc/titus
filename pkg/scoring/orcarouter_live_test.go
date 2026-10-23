package scoring

import (
	"context"
	"os"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOrcaRouterLive exercises the production code path — the real
// https://api.orcarouter.ai/v1/models origin, the real HTTP client and the
// real classifier — against a live OrcaRouter key supplied through the
// environment.
//
// It is skipped unless ORCAROUTER_API_KEY is set, so the normal test run stays
// hermetic and offline. The key is read directly from the environment, handed
// to the same conditions OrcaRouterGoScorer installs, and never printed or
// compared against a literal: assertions only inspect the classification
// result, and the log line reports booleans only.
func TestOrcaRouterLive(t *testing.T) {
	key := os.Getenv("ORCAROUTER_API_KEY")
	if key == "" {
		t.Skip("ORCAROUTER_API_KEY is not set; skipping the live provider check")
	}
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}

	match := &types.Match{
		RuleID:      orcaRouterRuleID,
		Groups:      [][]byte{[]byte(key)},
		NamedGroups: map[string][]byte{"key": []byte(key)},
	}

	// Score through the production scorer: real origin, default client, and the
	// shared probe cache that makes all four modifiers one request.
	scorer := OrcaRouterGoScorer()

	fired := map[string]bool{}
	for _, mod := range scorer.Modifiers {
		cond, ok := mod.Condition.(*orcaRouterCatalogCondition)
		require.Truef(t, ok, "modifier %q must be backed by the catalog condition", mod.Name)

		got, err := cond.Evaluate(context.Background(), match)
		require.NoErrorf(t, err, "modifier %q failed against the live catalog", mod.Name)
		fired[mod.Name] = got
	}

	// A catalog-reachable key is never reported as revoked, and a revoked key
	// never reports a catalog size.
	if fired["revoked-key"] {
		assert.False(t, fired["broad-model-access"], "a revoked key cannot expose models")
		assert.False(t, fired["limited-model-access"], "a revoked key cannot expose models")
		assert.False(t, fired["cyber-model-access"], "a revoked key cannot expose cyber models")
	} else {
		assert.True(t, fired["broad-model-access"] || fired["limited-model-access"],
			"a live key must be classified as either broad or limited access")
	}

	t.Logf("live catalog classification: cyber=%v broad=%v limited=%v revoked=%v",
		fired["cyber-model-access"], fired["broad-model-access"],
		fired["limited-model-access"], fired["revoked-key"])
}
