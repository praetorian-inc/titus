//go:build !wasm && cgo && vectorscan

package matcher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/flier/gohs/hyperscan"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHyperscanDatabaseRoundTrip(t *testing.T) {
	rules := hyperscanDatabaseTestRules()
	t.Setenv(CacheDirEnv, t.TempDir())
	dir, err := RulesCacheDir()
	require.NoError(t, err)

	path, err := WriteHyperscanDatabase(dir, rules)
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	_, err = hyperscan.SerializedDatabaseInfo(data)
	require.NoError(t, err, "the file should be a raw Hyperscan serialization")

	current, err := NewVectorscan(rules, 0, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, current.Close()) })
	matches, err := current.Match([]byte("secret_alpha TOKEN-1234"))
	require.NoError(t, err)
	assert.Len(t, matches, 2)
}

func TestHyperscanDatabaseCorruptionFallsBackToCompilation(t *testing.T) {
	rules := hyperscanDatabaseTestRules()
	filename, err := HyperscanDatabaseFilename(rules)
	require.NoError(t, err)
	t.Setenv(CacheDirEnv, t.TempDir())
	dir, err := RulesCacheDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, filename), []byte("not a database"), 0o600))

	var warnings []string
	current, err := NewVectorscan(rules, 0, func(format string, _ ...any) {
		warnings = append(warnings, format)
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, current.Close()) })
	assert.NotEmpty(t, warnings)
}

func TestHyperscanDatabaseFilenameIncludesPatternOrderAndFlags(t *testing.T) {
	rules := hyperscanDatabaseTestRules()
	base, err := HyperscanDatabaseFilename(rules)
	require.NoError(t, err)
	reversed, err := HyperscanDatabaseFilename([]*types.Rule{rules[1], rules[0]})
	require.NoError(t, err)
	assert.NotEqual(t, base, reversed)

	flagChanged := hyperscanDatabaseTestRules()
	flagChanged[0].Pattern = "(?i)" + flagChanged[0].Pattern
	withFlag, err := HyperscanDatabaseFilename(flagChanged)
	require.NoError(t, err)
	assert.NotEqual(t, base, withFlag)
}

func TestHyperscanDatabaseDifferentRulesCompileNormally(t *testing.T) {
	t.Setenv(CacheDirEnv, t.TempDir())
	dir, err := RulesCacheDir()
	require.NoError(t, err)
	_, err = WriteHyperscanDatabase(dir, hyperscanDatabaseTestRules())
	require.NoError(t, err)

	rules := []*types.Rule{{ID: "runtime-rule", Name: "Runtime rule", Pattern: `runtime_[a-z]+`}}
	current, err := NewVectorscan(rules, 0, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, current.Close()) })
	matches, err := current.Match([]byte("runtime_secret"))
	require.NoError(t, err)
	assert.Len(t, matches, 1)
}

func TestHyperscanDatabaseBuiltinRules(t *testing.T) {
	rules, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)
	t.Setenv(CacheDirEnv, t.TempDir())
	dir, err := RulesCacheDir()
	require.NoError(t, err)
	_, err = WriteHyperscanDatabase(dir, rules)
	require.NoError(t, err)

	current, err := NewVectorscan(rules, 0, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, current.Close()) })
	matches, err := current.Match([]byte("aws_access_key_id=AKIAIOSFODNN7EXAMPLE"))
	require.NoError(t, err)
	assert.NotEmpty(t, matches)
}

func hyperscanDatabaseTestRules() []*types.Rule {
	return []*types.Rule{
		{ID: "serialized-secret", Name: "Serialized secret", Pattern: `secret_[a-z]+`},
		{ID: "serialized-token", Name: "Serialized token", Pattern: `TOKEN-[0-9]+`},
	}
}
