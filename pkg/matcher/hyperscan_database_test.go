package matcher

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRulesCacheDirOverride(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv(CacheDirEnv, cacheDir)

	dir, err := RulesCacheDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(cacheDir, "rules"), dir)
}
