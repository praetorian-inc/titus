package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractCaptures_SimplePattern(t *testing.T) {
	content := []byte("My API key is AKIAIOSFODNN7EXAMPLE and that's it")
	pattern := `AKIA[0-9A-Z]{16}`
	start := 14
	end := 34

	captures, err := ExtractCaptures(content, pattern, start, end)

	require.NoError(t, err)
	assert.Empty(t, captures) // no capture groups, just a match
}

func TestExtractCaptures_WithCaptureGroups(t *testing.T) {
	content := []byte("Email: user@example.com")
	pattern := `(?P<user>[a-zA-Z0-9]+)@(?P<domain>[a-zA-Z0-9.]+)`
	start := 7
	end := 23

	captures, err := ExtractCaptures(content, pattern, start, end)

	require.NoError(t, err)
	assert.Equal(t, []byte("user"), captures["user"])
	assert.Equal(t, []byte("example.com"), captures["domain"])
}

func TestExtractCaptures_NoMatch(t *testing.T) {
	content := []byte("No match here")
	pattern := `AKIA[0-9A-Z]{16}`
	start := 0
	end := 13

	captures, err := ExtractCaptures(content, pattern, start, end)

	require.Error(t, err)
	assert.Nil(t, captures)
	assert.Contains(t, err.Error(), "pattern did not match")
}

func TestExtractCaptures_InvalidPattern(t *testing.T) {
	content := []byte("Some text")
	pattern := `[invalid(` // malformed regex
	start := 0
	end := 9

	captures, err := ExtractCaptures(content, pattern, start, end)

	require.Error(t, err)
	assert.Nil(t, captures)
	assert.Contains(t, err.Error(), "compile")
}

func TestExtractCaptures_OutOfBounds(t *testing.T) {
	content := []byte("Short")
	pattern := `.*`
	start := 0
	end := 100 // beyond content length

	captures, err := ExtractCaptures(content, pattern, start, end)

	require.Error(t, err)
	assert.Nil(t, captures)
	assert.Contains(t, err.Error(), "out of bounds")
}

func TestExtractCaptures_MultipleNamedGroups(t *testing.T) {
	content := []byte("aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	pattern := `aws_access_key_id=(?P<key>AKIA[0-9A-Z]{16})\naws_secret_access_key=(?P<secret>[A-Za-z0-9/+=]{40})`
	start := 0
	end := len(content)

	captures, err := ExtractCaptures(content, pattern, start, end)

	require.NoError(t, err)
	assert.Equal(t, []byte("AKIAIOSFODNN7EXAMPLE"), captures["key"])
	assert.Equal(t, []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), captures["secret"])
}

func TestExtractCaptures_UnnamedGroups(t *testing.T) {
	content := []byte("Value: 12345")
	pattern := `Value: (\d+)`
	start := 0
	end := 12

	captures, err := ExtractCaptures(content, pattern, start, end)

	require.NoError(t, err)
	// Unnamed groups are not included in the map
	assert.Empty(t, captures)
}

func TestExtractCaptures_MixedNamedAndUnnamed(t *testing.T) {
	content := []byte("Token: abc123xyz")
	pattern := `Token: ([a-z]+)(?P<numbers>\d+)([a-z]+)`
	start := 0
	end := 16

	captures, err := ExtractCaptures(content, pattern, start, end)

	require.NoError(t, err)
	// Only named group should be captured
	assert.Equal(t, []byte("123"), captures["numbers"])
	assert.Len(t, captures, 1)
}

func TestExtractCaptures_EmptyCapture(t *testing.T) {
	content := []byte("Optional: ")
	pattern := `Optional: (?P<value>.*)`
	start := 0
	end := 10

	captures, err := ExtractCaptures(content, pattern, start, end)

	require.NoError(t, err)
	assert.Equal(t, []byte(""), captures["value"])
}
