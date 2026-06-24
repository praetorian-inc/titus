package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSharePointEnumerator_ConstructionWithToken tests creation with a valid token config.
func TestSharePointEnumerator_ConstructionWithToken(t *testing.T) {
	e, err := NewSharePointEnumerator(SharePointConfig{
		Token: "test-bearer-token",
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}


// TestSharePointEnumerator_Interface verifies SharePointEnumerator implements Enumerator.
func TestSharePointEnumerator_Interface(t *testing.T) {
	e, err := NewSharePointEnumerator(SharePointConfig{
		Token: "test-bearer-token",
	})
	require.NoError(t, err)

	var _ Enumerator = e
}

// TestSharePointEnumerator_RequiresAuth tests that missing auth produces an error.
func TestSharePointEnumerator_RequiresAuth(t *testing.T) {
	_, err := NewSharePointEnumerator(SharePointConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}


// TestSharePointStripHTML tests the spStripHTML helper.
func TestSharePointStripHTML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "basic HTML",
			input:    "<p>Hello <b>world</b></p>",
			expected: "Hello world\n",
		},
		{
			name:     "HTML entities",
			input:    "foo &amp; bar &lt;baz&gt;",
			expected: "foo & bar <baz>",
		},
		{
			name:     "self-closing tags",
			input:    "line1<br/>line2",
			expected: "line1\nline2",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "no HTML",
			input:    "plain text content",
			expected: "plain text content",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, spStripHTML(tt.input))
		})
	}
}

// TestSharePointProvenance tests that spProvenance builds the correct ExtendedProvenance.
func TestSharePointProvenance(t *testing.T) {
	prov := spProvenance("Engineering", "/sites/eng/Shared Documents/config.json", "config.json", "https://company.sharepoint.com/sites/eng/config.json")

	payload := prov.Payload
	require.NotNil(t, payload)
	assert.Equal(t, "sharepoint", payload["source"])
	assert.Equal(t, "Engineering", payload["site"])
	assert.Equal(t, "/sites/eng/Shared Documents/config.json", payload["path"])
	assert.Equal(t, "config.json", payload["title"])
	assert.Equal(t, "https://company.sharepoint.com/sites/eng/config.json", payload["url"])
}
