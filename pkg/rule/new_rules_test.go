package rule

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatadogRUMToken_Detection verifies the kingfisher.datadog.4 rule
// detects Datadog RUM client tokens with pub prefix
func TestDatadogRUMToken_Detection(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	// Find the Datadog RUM token rule
	var rumRule *types.Rule
	for _, r := range rules {
		if r.ID == "kingfisher.datadog.4" {
			rumRule = r
			break
		}
	}
	require.NotNil(t, rumRule, "kingfisher.datadog.4 rule should exist")

	// Create matcher with just this rule
	m, err := matcher.NewPortableRegexp([]*types.Rule{rumRule}, 0, nil)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "valid DATADOG_RUM_TOKEN",
			input:       `DATADOG_RUM_TOKEN=pub0123456789abcdef0123456789abcdef`,
			shouldMatch: true,
		},
		{
			name:        "valid DD_TOKEN with quotes",
			input:       `DD_TOKEN="pubabcdef0123456789abcdef0123456789"`,
			shouldMatch: true,
		},
		{
			name:        "valid DATADOG_TOKEN",
			input:       `DATADOG_TOKEN:pubfedcba9876543210fedcba9876543210`,
			shouldMatch: true,
		},
		{
			name:        "valid JSON format",
			input:       `"DATADOG_RUM_TOKEN":"pub0123456789abcdef0123456789abcdef"`,
			shouldMatch: true,
		},
		{
			name:        "invalid - missing pub prefix",
			input:       `DATADOG_RUM_TOKEN=abc0123456789abcdef0123456789abcd`,
			shouldMatch: false,
		},
		{
			name:        "invalid - too short",
			input:       `DATADOG_RUM_TOKEN=pub0123456789`,
			shouldMatch: false,
		},
		{
			name:        "invalid - wrong characters",
			input:       `DATADOG_RUM_TOKEN=pubGHIJKL6789abcdef0123456789abcd`,
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.input))
			require.NoError(t, err)

			if tc.shouldMatch {
				assert.NotEmpty(t, matches, "expected match for: %s", tc.input)
			} else {
				assert.Empty(t, matches, "expected no match for: %s", tc.input)
			}
		})
	}
}

// TestLaunchDarklyClientSideID_Detection verifies the kingfisher.launchdarkly.2 rule
// detects LaunchDarkly client-side IDs
func TestLaunchDarklyClientSideID_Detection(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	// Find the LaunchDarkly client-side ID rule
	var ldRule *types.Rule
	for _, r := range rules {
		if r.ID == "kingfisher.launchdarkly.2" {
			ldRule = r
			break
		}
	}
	require.NotNil(t, ldRule, "kingfisher.launchdarkly.2 rule should exist")

	// Create matcher with just this rule
	m, err := matcher.NewPortableRegexp([]*types.Rule{ldRule}, 0, nil)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "valid LD_CLIENT_SIDE_ID",
			input:       `LD_CLIENT_SIDE_ID=0123456789abcdef01234567`,
			shouldMatch: true,
		},
		{
			name:        "valid LAUNCHDARKLY_CLIENT_ID with quotes",
			input:       `LAUNCHDARKLY_CLIENT_ID="abcdef0123456789abcdef01"`,
			shouldMatch: true,
		},
		{
			name:        "valid LD_CLIENT_ID with colon",
			input:       `LD_CLIENT_ID:fedcba9876543210fedcba98`,
			shouldMatch: true,
		},
		{
			name:        "valid JSON format",
			input:       `"LD_CLIENT_SIDE_ID":"0123456789abcdef01234567"`,
			shouldMatch: true,
		},
		{
			name:        "invalid - too short",
			input:       `LD_CLIENT_SIDE_ID=0123456789abcdef`,
			shouldMatch: false,
		},
		{
			name:        "invalid - too long",
			input:       `LD_CLIENT_SIDE_ID=0123456789abcdef0123456789abcdef`,
			shouldMatch: false,
		},
		{
			name:        "invalid - non-hex characters",
			input:       `LD_CLIENT_SIDE_ID=ghijklmnopqrstuvwxyz1234`,
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.input))
			require.NoError(t, err)

			if tc.shouldMatch {
				assert.NotEmpty(t, matches, "expected match for: %s", tc.input)
			} else {
				assert.Empty(t, matches, "expected no match for: %s", tc.input)
			}
		})
	}
}

// TestSentryDSN_Detection verifies the kingfisher.sentry.4 rule
// detects Sentry DSN URLs
func TestSentryDSN_Detection(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	// Find the Sentry DSN rule
	var dsnRule *types.Rule
	for _, r := range rules {
		if r.ID == "kingfisher.sentry.4" {
			dsnRule = r
			break
		}
	}
	require.NotNil(t, dsnRule, "kingfisher.sentry.4 rule should exist")

	// Create matcher with just this rule
	m, err := matcher.NewPortableRegexp([]*types.Rule{dsnRule}, 0, nil)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "valid SENTRY_DSN basic",
			input:       `SENTRY_DSN=https://0123456789abcdef0123456789abcdef@sentry.io/12345`,
			shouldMatch: true,
		},
		{
			name:        "valid SENTRY_DSN with org subdomain",
			input:       `SENTRY_DSN="https://abcdef0123456789abcdef0123456789@o123456.sentry.io/67890"`,
			shouldMatch: true,
		},
		{
			name:        "valid DSN without variable prefix",
			input:       `https://fedcba9876543210fedcba9876543210@sentry.io/99999`,
			shouldMatch: true,
		},
		{
			name:        "valid self-hosted DSN",
			input:       `SENTRY_DSN=https://0123456789abcdef0123456789abcdef@sentry.example.com/11111`,
			shouldMatch: true,
		},
		{
			name:        "invalid - missing https",
			input:       `SENTRY_DSN=http://0123456789abcdef0123456789abcdef@sentry.io/12345`,
			shouldMatch: false,
		},
		{
			name:        "invalid - key too short",
			input:       `SENTRY_DSN=https://0123456789abcdef@sentry.io/12345`,
			shouldMatch: false,
		},
		{
			name:        "invalid - non-numeric project ID",
			input:       `SENTRY_DSN=https://0123456789abcdef0123456789abcdef@sentry.io/abc`,
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := m.Match([]byte(tc.input))
			require.NoError(t, err)

			if tc.shouldMatch {
				assert.NotEmpty(t, matches, "expected match for: %s", tc.input)
			} else {
				assert.Empty(t, matches, "expected no match for: %s", tc.input)
			}
		})
	}
}

// TestNewRules_RuleExistence verifies all new rules are properly loaded
func TestNewRules_RuleExistence(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	expectedRules := []struct {
		id   string
		name string
	}{
		{"kingfisher.datadog.4", "Datadog RUM Client Token"},
		{"kingfisher.launchdarkly.2", "LaunchDarkly Client-side ID"},
		{"kingfisher.sentry.4", "Sentry DSN"},
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	for _, expected := range expectedRules {
		t.Run(expected.id, func(t *testing.T) {
			rule, exists := ruleMap[expected.id]
			assert.True(t, exists, "rule %s should exist", expected.id)
			if exists {
				assert.Equal(t, expected.name, rule.Name, "rule name mismatch")
				assert.NotEmpty(t, rule.Pattern, "rule should have a pattern")
				assert.NotEmpty(t, rule.Examples, "rule should have examples")
			}
		})
	}
}
