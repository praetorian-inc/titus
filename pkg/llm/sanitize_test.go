package llm

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitize_StripNullBytes(t *testing.T) {
	assert.Equal(t, "hello world", Sanitize("hello\x00 world"))
}

func TestSanitize_StripANSI(t *testing.T) {
	assert.Equal(t, "hello", Sanitize("\x1b[31mhello\x1b[0m"))
}

func TestSanitize_StripControlChars(t *testing.T) {
	assert.Equal(t, "ab", Sanitize("a\x01\x02\x03\x04\x05\x06\x07b"))
}

func TestSanitize_PreservesNewlinesAndTabs(t *testing.T) {
	assert.Equal(t, "a\nb\tc", Sanitize("a\nb\tc"))
}

func TestTruncateBody_Short(t *testing.T) {
	body := []byte("short")
	assert.Equal(t, "short", TruncateBody(body, 2048))
}

func TestTruncateBody_Long(t *testing.T) {
	body := []byte(strings.Repeat("x", 3000))
	result := TruncateBody(body, 2048)
	assert.Len(t, result, 2048+len("... [truncated]"))
	assert.True(t, strings.HasSuffix(result, "... [truncated]"))
}

func TestTruncateBody_ExactLimit(t *testing.T) {
	body := []byte(strings.Repeat("x", 2048))
	assert.Equal(t, string(body), TruncateBody(body, 2048))
}

func TestWrapUntrusted(t *testing.T) {
	result := WrapUntrusted("response_body", "some content")
	assert.Contains(t, result, "<response_body>")
	assert.Contains(t, result, "some content")
	assert.Contains(t, result, "</response_body>")
}

func TestWrapUntrusted_SanitizesContent(t *testing.T) {
	result := WrapUntrusted("body", "hello\x00world")
	assert.NotContains(t, result, "\x00")
	assert.Contains(t, result, "helloworld")
}
