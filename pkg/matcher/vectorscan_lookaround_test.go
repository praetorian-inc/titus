//go:build !wasm && cgo && vectorscan

package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStripLookarounds_NegativeLookaheadWithNestedGroups mirrors the np.generic.5
// pattern (after extended-mode strip) and verifies the lookahead group is fully
// removed while the surrounding pattern — including the capture group — is kept.
func TestStripLookarounds_NegativeLookaheadWithNestedGroups(t *testing.T) {
	// This is what np.generic.5 looks like after stripExtendedMode processes it.
	input := `password"(?!(?-i)[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")([^"]{4,})"`
	want := `password"([^"]{4,})"`
	got := stripLookarounds(input)
	assert.Equal(t, want, got)
}

// TestStripLookarounds_CharClassSafety verifies that parentheses inside a character
// class are NOT counted as group delimiters.
func TestStripLookarounds_CharClassSafety(t *testing.T) {
	// The (?!...) contains a character class with ) and ( inside it.
	// The lookahead must still be fully consumed and the rest preserved.
	input := `foo(?![()-])bar`
	want := `foobar`
	got := stripLookarounds(input)
	assert.Equal(t, want, got)
}

// TestStripLookarounds_EscapedParenSafety verifies that \( and \) are preserved
// verbatim and are not counted as group delimiters.
func TestStripLookarounds_EscapedParenSafety(t *testing.T) {
	// Pattern has escaped parens outside a lookaround — must be unchanged.
	input := `\(hello\)(?=world)suffix`
	want := `\(hello\)suffix`
	got := stripLookarounds(input)
	assert.Equal(t, want, got)
}

// TestStripLookarounds_NoLookaround verifies patterns without any lookaround are
// returned unchanged.
func TestStripLookarounds_NoLookaround(t *testing.T) {
	cases := []string{
		`foo(bar)baz`,
		`[A-Z]+`,
		`(?:abc)`,
		`(?i)sensitive`,
		`(?P<name>[a-z]+)`,
		``,
	}
	for _, c := range cases {
		assert.Equal(t, c, stripLookarounds(c), "pattern should be unchanged: %q", c)
	}
}

// TestStripLookarounds_AllLookaroundTypes checks that all four lookaround forms
// are recognised and removed.
func TestStripLookarounds_AllLookaroundTypes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"positive lookahead", `foo(?=bar)baz`, `foobaz`},
		{"negative lookahead", `foo(?!bar)baz`, `foobaz`},
		{"positive lookbehind", `foo(?<=bar)baz`, `foobaz`},
		{"negative lookbehind", `foo(?<!bar)baz`, `foobaz`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, stripLookarounds(tc.input))
		})
	}
}

// TestStripLookarounds_MalformedUnclosed verifies that a lookaround group that
// is never closed causes the remainder of the pattern (from the lookaround
// start) to be dropped. This is safe: a malformed pattern would fail Hyperscan
// compilation regardless, and regexp2 always uses the unmodified rule.Pattern.
func TestStripLookarounds_MalformedUnclosed(t *testing.T) {
	got := stripLookarounds("foo(?=bar")
	assert.Equal(t, "foo", got)
}

// TestLookaroundEnd_Unbalanced verifies that lookaroundEnd returns len(runes)
// when the group starting at start is never closed.
func TestLookaroundEnd_Unbalanced(t *testing.T) {
	runes := []rune("(?=bar") // no closing ')'
	end := lookaroundEnd(runes, 0)
	assert.Equal(t, len(runes), end)
}

// TestStripLookarounds_MultipleAdjacent verifies that multiple consecutive
// lookarounds are all removed and the surrounding literal text is preserved.
func TestStripLookarounds_MultipleAdjacent(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			"lookahead then lookbehind separated by literal",
			`foo(?=bar)mid(?!baz)end`,
			`foomidend`,
		},
		{
			"two adjacent lookarounds with no literal between",
			`pre(?=x)(?!y)post`,
			`prepost`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, stripLookarounds(tc.input))
		})
	}
}

// TestStripLookarounds_LookbehindAdjacentToNamedGroup verifies that a lookbehind
// immediately followed by a .NET-style named group does NOT clobber the named
// group — only the lookbehind is stripped.
func TestStripLookarounds_LookbehindAdjacentToNamedGroup(t *testing.T) {
	input := `foo(?<=bar)(?<name>baz)`
	want := `foo(?<name>baz)`
	got := stripLookarounds(input)
	assert.Equal(t, want, got)
}

// TestVectorscanMatcher_NoFallbackRulesAfterLookaroundStrip loads all built-in
// rules, builds a VectorscanMatcher, and asserts that np.generic.5 and
// np.generic.6 are NOT in the fallback set — i.e., they were successfully
// compiled into Hyperscan after lookaround stripping.
func TestVectorscanMatcher_NoFallbackRulesAfterLookaroundStrip(t *testing.T) {
	rules, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	m, err := NewVectorscan(rules, 0, nil)
	require.NoError(t, err)
	// Skip defer Close — pre-existing hyperscan cleanup issue can cause hangs.

	// Build a set of fallback rule IDs for O(1) lookup.
	fallbackIDs := make(map[string]bool, len(m.fallbackRules))
	for _, r := range m.fallbackRules {
		fallbackIDs[r.ID] = true
	}

	assert.False(t, fallbackIDs["np.generic.5"], "np.generic.5 should be compiled into Hyperscan, not fallback")
	assert.False(t, fallbackIDs["np.generic.6"], "np.generic.6 should be compiled into Hyperscan, not fallback")
	assert.Equal(t, 0, len(m.fallbackRules), "expected 0 fallback rules, got %d", len(m.fallbackRules))
}

