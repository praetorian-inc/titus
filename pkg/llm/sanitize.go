package llm

import (
	"fmt"
	"regexp"
	"strings"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// Sanitize strips ANSI escape sequences and control characters (including
// null bytes) from input, while preserving newlines, carriage returns, and
// tabs. It is used to clean untrusted text before including it in an LLM
// prompt.
func Sanitize(input string) string {
	input = ansiPattern.ReplaceAllString(input, "")
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TruncateBody returns body as a string, truncated to maxLen bytes with a
// "... [truncated]" suffix appended if it exceeds maxLen.
func TruncateBody(body []byte, maxLen int) string {
	if len(body) <= maxLen {
		return string(body)
	}
	return string(body[:maxLen]) + "... [truncated]"
}

// WrapUntrusted sanitizes content and wraps it in an XML-style tag, to
// clearly delineate untrusted input within an LLM prompt as a mitigation
// against prompt injection.
func WrapUntrusted(tag, content string) string {
	content = Sanitize(content)
	return fmt.Sprintf("<%s>\n%s\n</%s>", tag, content, tag)
}
