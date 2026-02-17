//go:build !wasm

package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStripExtendedMode_AWSPattern(t *testing.T) {
	// Test the actual np.aws.6 pattern
	input := `(?x)
\b
((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})     (?# API key )
\b
(?: (?s) .{0,40} )                                                        (?# Arbitrary intermediate stuff; ?s causes . to match newlines )
\b
([A-Za-z0-9/+=]{40})                                                      (?# secret )
(?: [^A-Za-z0-9/+=] | $ )`

	result := stripExtendedMode(input)
	// Hyperscan DotAll flag handles newlines, so . stays as .
	expected := `\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b(?:.{0,40})\b([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)`

	t.Logf("Input:\n%s", input)
	t.Logf("Result:\n%s", result)
	t.Logf("Expected:\n%s", expected)

	assert.Equal(t, expected, result)
}

func TestStripExtendedMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "pattern with (?x) and comments",
			input: `(?x)
\b
((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})     (?# API key )
\b`,
			expected: `\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b`,
		},
		{
			name:     "pattern without (?x)",
			input:    `\b(test)\b`,
			expected: `\b(test)\b`,
		},
		{
			name: "pattern with (?x) and multiple comments",
			input: `(?x)
\b
([A-Z]+)    (?# match letters )
\d+         (?# match digits )
\b`,
			expected: `\b([A-Z]+)\d+\b`,
		},
		{
			name: "pattern with (?x) preserving escaped spaces",
			input: `(?x)
test\ pattern    (?# with escaped space )
\s+`,
			expected: `test\ pattern\s+`,
		},
		{
			name:     "pattern with (?x) only (no whitespace)",
			input:    `(?x)\btest\b`,
			expected: `\btest\b`,
		},
		{
			name:     "pattern with (?s) modifier removed but dot unchanged",
			input:    `(?x) (?s) .{0,40}`,
			expected: `.{0,40}`,
		},
		{
			name:     "pattern with dot in character class and outside (both unchanged)",
			input:    `(?x) [.abc]+ (?s) .+`,
			expected: `[.abc]+.+`,
		},
		{
			name:     "pattern with escaped dot and unescaped dot (both unchanged)",
			input:    `(?x) (?s) \. .+`,
			expected: `\..+`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripExtendedMode(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
