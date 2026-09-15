//go:build !wasm && !vectorscan

package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_KeepAllMatches(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-rule",
			Name:    "Test API Key Pattern",
			Pattern: `api_key\s*=\s*"([^"]+)"`,
		},
	}
	content := []byte(`api_key = "key456"` + "\n" +
		`other line` + "\n" +
		`api_key = "key456"` + "\n")

	m, err := New(Config{Rules: rules})
	require.NoError(t, err)
	defer func() { _ = m.Close() }()

	matches, err := m.Match(content)
	require.NoError(t, err)
	assert.Len(t, matches, 1, "default should collapse repeated occurrences of the same secret within a blob")

	m2, err := New(Config{Rules: rules, KeepAllMatches: true})
	require.NoError(t, err)
	defer func() { _ = m2.Close() }()

	matches, err = m2.Match(content)
	require.NoError(t, err)
	require.Len(t, matches, 2, "KeepAllMatches should preserve every location-distinct occurrence")
	assert.NotEqual(t, matches[0].Location.Offset.Start, matches[1].Location.Offset.Start,
		"occurrences should have distinct locations")
}
