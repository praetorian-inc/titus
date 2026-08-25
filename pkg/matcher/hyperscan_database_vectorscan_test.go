//go:build !wasm && cgo && vectorscan

package matcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/flier/gohs/hyperscan"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHyperscanDatabaseRoundTrip(t *testing.T) {
	rules := hyperscanDatabaseTestRules()
	t.Setenv(CacheDirEnv, t.TempDir())
	path := hyperscanDatabaseTestPath(t, rules)

	_, err := os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)

	current, err := NewVectorscan(rules, 0, nil)
	require.NoError(t, err)
	require.NoError(t, current.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	_, err = hyperscan.SerializedDatabaseInfo(data)
	require.NoError(t, err, "the file should be a raw Hyperscan serialization")

	oldModTime := time.Unix(946684800, 0)
	require.NoError(t, os.Chtimes(path, oldModTime, oldModTime))

	current, err = NewVectorscan(rules, 0, nil)
	require.NoError(t, err)
	matches, err := current.Match([]byte("secret_alpha TOKEN-1234"))
	require.NoError(t, err)
	assert.Len(t, matches, 2)
	require.NoError(t, current.Close())

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, oldModTime, info.ModTime(), "a cache hit should not rewrite the database")
}

func TestHyperscanDatabaseCorruptionFallsBackToCompilation(t *testing.T) {
	rules := hyperscanDatabaseTestRules()
	t.Setenv(CacheDirEnv, t.TempDir())
	path := hyperscanDatabaseTestPath(t, rules)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte("not a database"), 0o600))

	var warnings []string
	current, err := NewVectorscan(rules, 0, func(format string, _ ...any) {
		warnings = append(warnings, format)
	})
	require.NoError(t, err)
	require.NoError(t, current.Close())
	assert.NotEmpty(t, warnings)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	_, err = hyperscan.SerializedDatabaseInfo(data)
	require.NoError(t, err, "normal compilation should replace the corrupt cache")
}

func TestHyperscanDatabaseFilenameIncludesPatternOrderAndFlags(t *testing.T) {
	rules := hyperscanDatabaseTestRules()
	base := hyperscanDatabaseFilename(hyperscanPatterns(rules))
	reversed := hyperscanDatabaseFilename(hyperscanPatterns([]*types.Rule{rules[1], rules[0]}))
	assert.NotEqual(t, base, reversed)

	flagChanged := hyperscanDatabaseTestRules()
	flagChanged[0].Pattern = "(?i)" + flagChanged[0].Pattern
	withFlag := hyperscanDatabaseFilename(hyperscanPatterns(flagChanged))
	assert.NotEqual(t, base, withFlag)
}

func TestHyperscanDatabaseCachesDifferentRuntimeRules(t *testing.T) {
	t.Setenv(CacheDirEnv, t.TempDir())
	builtinVariant := hyperscanDatabaseTestRules()
	builtinPath := hyperscanDatabaseTestPath(t, builtinVariant)
	current, err := NewVectorscan(builtinVariant, 0, nil)
	require.NoError(t, err)
	require.NoError(t, current.Close())
	require.FileExists(t, builtinPath)

	rules := []*types.Rule{{ID: "runtime-rule", Name: "Runtime rule", Pattern: `runtime_[a-z]+`}}
	runtimePath := hyperscanDatabaseTestPath(t, rules)
	current, err = NewVectorscan(rules, 0, nil)
	require.NoError(t, err)
	matches, err := current.Match([]byte("runtime_secret"))
	require.NoError(t, err)
	assert.Len(t, matches, 1)
	require.NoError(t, current.Close())
	require.FileExists(t, runtimePath)
	assert.NotEqual(t, builtinPath, runtimePath)
}

func TestHyperscanDatabaseBuiltinRules(t *testing.T) {
	rules, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)
	t.Setenv(CacheDirEnv, t.TempDir())
	path := hyperscanDatabaseTestPath(t, rules)

	current, err := NewVectorscan(rules, 0, nil)
	require.NoError(t, err)
	matches, err := current.Match([]byte("aws_access_key_id=AKIAIOSFODNN7EXAMPLE"))
	require.NoError(t, err)
	assert.NotEmpty(t, matches)
	require.NoError(t, current.Close())
	require.FileExists(t, path)
}

func TestHyperscanDatabaseCacheFailureDoesNotPreventScanning(t *testing.T) {
	cacheRoot := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(cacheRoot, []byte("file"), 0o600))
	t.Setenv(CacheDirEnv, cacheRoot)

	var warnings []string
	current, err := NewVectorscan(hyperscanDatabaseTestRules(), 0, func(format string, _ ...any) {
		warnings = append(warnings, format)
	})
	require.NoError(t, err)
	require.NoError(t, current.Close())
	assert.NotEmpty(t, warnings)
}

func hyperscanDatabaseTestRules() []*types.Rule {
	return []*types.Rule{
		{ID: "serialized-secret", Name: "Serialized secret", Pattern: `secret_[a-z]+`},
		{ID: "serialized-token", Name: "Serialized token", Pattern: `TOKEN-[0-9]+`},
	}
}

func hyperscanDatabaseTestPath(t *testing.T, rules []*types.Rule) string {
	t.Helper()
	dir, err := RulesCacheDir()
	require.NoError(t, err)
	return filepath.Join(dir, hyperscanDatabaseFilename(hyperscanPatterns(rules)))
}
