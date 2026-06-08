package scoring

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDigestChallenge_StandardFields(t *testing.T) {
	header := `Digest realm="cloud.mongodb.com", nonce="abc123", qop="auth", opaque="xyz"`
	params := parseDigestChallenge(header)
	assert.Equal(t, "cloud.mongodb.com", params["realm"])
	assert.Equal(t, "abc123", params["nonce"])
	assert.Equal(t, "auth", params["qop"])
	assert.Equal(t, "xyz", params["opaque"])
}

func TestParseDigestChallenge_UnquotedValues(t *testing.T) {
	header := `Digest realm="example.com", qop=auth, nonce="n1"`
	params := parseDigestChallenge(header)
	assert.Equal(t, "auth", params["qop"])
	assert.Equal(t, "example.com", params["realm"])
	assert.Equal(t, "n1", params["nonce"])
}

func TestBuildDigestAuthHeader_QopAuth(t *testing.T) {
	wwwAuth := `Digest realm="cloud.mongodb.com", nonce="testnonce", qop="auth"`
	result, err := buildDigestAuthHeader("user", "pass", "GET", "https://cloud.mongodb.com/api/atlas/v2/groups", wwwAuth)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result, `Digest username="user"`))
	assert.True(t, strings.Contains(result, `realm="cloud.mongodb.com"`))
	assert.True(t, strings.Contains(result, `nonce="testnonce"`))
	assert.True(t, strings.Contains(result, `qop=auth`))
	assert.True(t, strings.Contains(result, `nc=00000001`))
	assert.True(t, strings.Contains(result, `cnonce=`))
	assert.True(t, strings.Contains(result, `uri="/api/atlas/v2/groups"`))
	assert.True(t, strings.Contains(result, `response="`))
}

func TestBuildDigestAuthHeader_NoQop(t *testing.T) {
	wwwAuth := `Digest realm="test", nonce="n1"`
	result, err := buildDigestAuthHeader("u", "p", "GET", "https://example.com/path", wwwAuth)
	require.NoError(t, err)
	assert.True(t, strings.Contains(result, `response="`))
	assert.False(t, strings.Contains(result, `qop=`))
	assert.False(t, strings.Contains(result, `nc=`))
	assert.False(t, strings.Contains(result, `cnonce=`))
}

func TestBuildDigestAuthHeader_MissingRealmOrNonce_ReturnsError(t *testing.T) {
	wwwAuth := `Digest qop="auth"`
	_, err := buildDigestAuthHeader("user", "pass", "GET", "https://example.com/path", wwwAuth)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "missing realm or nonce"))
}
