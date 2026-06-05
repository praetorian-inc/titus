package scoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

const testPNSubKey = "sub-c-test0000-exam-ple0-fake-000000000000"
const testPNPubKey = "pub-c-test0000-exam-ple0-fake-000000000000"

func pubnubSubMatch() *types.Match {
	return &types.Match{
		RuleID: "kingfisher.pubnub.2",
		Groups: [][]byte{[]byte(testPNSubKey)},
	}
}

func pubnubPubMatch() *types.Match {
	return &types.Match{
		RuleID: "kingfisher.pubnub.1",
		Groups: [][]byte{[]byte(testPNPubKey)},
		Snippet: types.Snippet{
			After: []byte("SUBSCRIBE_KEY=" + testPNSubKey + "\n"),
		},
	}
}

// pubnubRedirectingClient redirects all requests to a test server URL.
type pubnubRedirectingClient struct {
	target string
}

func (c *pubnubRedirectingClient) Do(req *http.Request) (*http.Response, error) {
	testURL := c.target + req.URL.Path
	if req.URL.RawQuery != "" {
		testURL += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, testURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return http.DefaultClient.Do(newReq)
}

func TestExtractPubNubKey_FromGroups(t *testing.T) {
	m := pubnubSubMatch()
	key, ok := extractPubNubKey(m)
	assert.True(t, ok)
	assert.Equal(t, testPNSubKey, key)
}

func TestExtractPubNubKey_Missing(t *testing.T) {
	m := &types.Match{RuleID: "kingfisher.pubnub.2", Groups: [][]byte{}}
	_, ok := extractPubNubKey(m)
	assert.False(t, ok)
}

func TestPubNubKeyExpiredCondition_SubKey_Expired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	c := &pubnubKeyExpiredCondition{client: &pubnubRedirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), pubnubSubMatch())
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestPubNubKeyExpiredCondition_SubKey_Active(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := &pubnubKeyExpiredCondition{client: &pubnubRedirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), pubnubSubMatch())
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestPubNubKeyExpiredCondition_PubKey_Expired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	c := &pubnubKeyExpiredCondition{client: &pubnubRedirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), pubnubPubMatch())
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestPubNubActiveKeyCondition_Active(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := &pubnubActiveKeyCondition{client: &pubnubRedirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), pubnubSubMatch())
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestPubNubActiveKeyCondition_Inactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	c := &pubnubActiveKeyCondition{client: &pubnubRedirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), pubnubSubMatch())
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestPubNubNoAccessManagerCondition_Disabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200 = no access manager
	}))
	defer server.Close()

	c := &pubnubNoAccessManagerCondition{client: &pubnubRedirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), pubnubSubMatch())
	assert.NoError(t, err)
	assert.True(t, fired)
}

func TestPubNubNoAccessManagerCondition_Enabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 403 = access manager on
	}))
	defer server.Close()

	c := &pubnubNoAccessManagerCondition{client: &pubnubRedirectingClient{target: server.URL}}
	fired, err := c.Evaluate(context.Background(), pubnubSubMatch())
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestPubNubNoAccessManagerCondition_PubKeySkipped(t *testing.T) {
	// No-access-manager check only applies to sub keys
	c := &pubnubNoAccessManagerCondition{}
	fired, err := c.Evaluate(context.Background(), pubnubPubMatch())
	assert.NoError(t, err)
	assert.False(t, fired)
}

func TestPubNubGoScorer_Structure(t *testing.T) {
	s := PubNubGoScorer()
	assert.Equal(t, "pubnub-scope", s.Name)
	assert.Contains(t, s.RuleIDs, "kingfisher.pubnub.1")
	assert.Contains(t, s.RuleIDs, "kingfisher.pubnub.2")
	assert.Equal(t, 3, len(s.Modifiers))
}

func TestPubNubGoScorer_MissingKey(t *testing.T) {
	s := PubNubGoScorer()
	m := &types.Match{
		RuleID: "kingfisher.pubnub.2",
		Groups: [][]byte{},
	}
	for _, mod := range s.Modifiers {
		fired, err := mod.Condition.Evaluate(context.Background(), m)
		assert.NoError(t, err, "modifier %s should not error", mod.Name)
		assert.False(t, fired, "modifier %s should not fire without key", mod.Name)
	}
}
