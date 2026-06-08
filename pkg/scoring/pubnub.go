package scoring

import (
	"context"
	"io"
	"net/http"
	"regexp"

	"github.com/praetorian-inc/titus/pkg/types"
)

var pubnubSubKeyPattern = regexp.MustCompile(`\b(sub-c-[a-z0-9]{8}(?:-[a-z0-9]{4}){3}-[a-z0-9]{12})\b`)

// pubnubSearchSnippet searches all three snippet parts against patterns,
// returning the first captured group match.
func pubnubSearchSnippet(snippet types.Snippet, patterns []*regexp.Regexp) string {
	parts := [][]byte{snippet.Before, snippet.Matching, snippet.After}
	for _, pattern := range patterns {
		for _, part := range parts {
			if matches := pattern.FindSubmatch(part); len(matches) >= 2 {
				return string(matches[1])
			}
		}
	}
	return ""
}

// extractPubNubKey extracts the key from positional group 1 or named groups.
func extractPubNubKey(m *types.Match) (string, bool) {
	if m == nil {
		return "", false
	}
	if len(m.Groups) > 0 && len(m.Groups[0]) > 0 {
		return string(m.Groups[0]), true
	}
	for _, name := range []string{"token", "key", "1"} {
		if v, ok := m.NamedGroups[name]; ok && len(v) > 0 {
			return string(v), true
		}
	}
	return "", false
}

// pubnubHTTPClient is an interface for making HTTP requests (allows testing).
type pubnubHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// pubnubKeyExpiredCondition fires when the key returns 401/403.
type pubnubKeyExpiredCondition struct {
	client pubnubHTTPClient
}

func (c *pubnubKeyExpiredCondition) markDynamic() {}

func (c *pubnubKeyExpiredCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	key, ok := extractPubNubKey(m)
	if !ok {
		return false, nil
	}

	// For sub keys, check the objects endpoint directly.
	// For pub keys, we need a sub key — if not available, skip.
	url := "https://ps.pndsn.com/v2/objects/" + key + "/uuids/titus_score"
	if m.RuleID == "kingfisher.pubnub.1" {
		// Pub key — need sub key from snippet
		subKey := pubnubSearchSnippet(m.Snippet, []*regexp.Regexp{pubnubSubKeyPattern})
		if subKey == "" {
			return false, nil
		}
		url = "https://ps.pndsn.com/publish/" + key + "/" + subKey + "/0/titus_score/0/%22ping%22"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, nil
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	return resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden, nil
}

func (c *pubnubKeyExpiredCondition) httpClient() pubnubHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// pubnubActiveKeyCondition fires when the key is confirmed active (200).
type pubnubActiveKeyCondition struct {
	client pubnubHTTPClient
}

func (c *pubnubActiveKeyCondition) markDynamic() {}

func (c *pubnubActiveKeyCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	key, ok := extractPubNubKey(m)
	if !ok {
		return false, nil
	}

	url := "https://ps.pndsn.com/v2/objects/" + key + "/uuids/titus_score"
	if m.RuleID == "kingfisher.pubnub.1" {
		subKey := pubnubSearchSnippet(m.Snippet, []*regexp.Regexp{pubnubSubKeyPattern})
		if subKey == "" {
			return false, nil
		}
		url = "https://ps.pndsn.com/publish/" + key + "/" + subKey + "/0/titus_score/0/%22ping%22"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, nil
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	return resp.StatusCode == http.StatusOK, nil
}

func (c *pubnubActiveKeyCondition) httpClient() pubnubHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// pubnubNoAccessManagerCondition fires when Access Manager is disabled,
// meaning anyone with the key can publish/subscribe without authentication.
// Detected by a successful unauthenticated request (200 instead of 403).
type pubnubNoAccessManagerCondition struct {
	client pubnubHTTPClient
}

func (c *pubnubNoAccessManagerCondition) markDynamic() {}

func (c *pubnubNoAccessManagerCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	key, ok := extractPubNubKey(m)
	if !ok {
		return false, nil
	}

	// Only check sub keys — if Access Manager is off, the objects endpoint returns 200
	// without any auth token. If AM is on, it returns 403.
	if m.RuleID != "kingfisher.pubnub.2" {
		return false, nil
	}

	url := "https://ps.pndsn.com/v2/objects/" + key + "/uuids/titus_score"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, nil
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	// 200 without auth = Access Manager disabled = higher risk
	return resp.StatusCode == http.StatusOK, nil
}

func (c *pubnubNoAccessManagerCondition) httpClient() pubnubHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// PubNubGoScorer returns the PubNub scoring configuration.
func PubNubGoScorer() *Scorer {
	return &Scorer{
		Name:    "pubnub-scope",
		RuleIDs: []string{"kingfisher.pubnub.1", "kingfisher.pubnub.2"},
		Modifiers: []Modifier{
			// Priority 100: Key expired/invalid → set_score 5
			{
				Name:      "key-expired",
				Priority:  100,
				Kind:      ModifierKindSetScore,
				Value:     5,
				Condition: &pubnubKeyExpiredCondition{},
			},
			// Priority 90: Key confirmed active → delta +5
			{
				Name:      "active-key",
				Priority:  90,
				Kind:      ModifierKindDelta,
				Value:     5,
				Condition: &pubnubActiveKeyCondition{},
			},
			// Priority 80: Access Manager disabled → delta +10
			{
				Name:      "no-access-manager",
				Priority:  80,
				Kind:      ModifierKindDelta,
				Value:     10,
				Condition: &pubnubNoAccessManagerCondition{},
			},
		},
	}
}
