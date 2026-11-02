package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnumHuman_CountsSharedFindingOnce asserts that when many files hold the
// same secret, the summary counts every match but the finding exactly once,
// even though the filesystem enumerator yields blobs from parallel readers.
func TestEnumHuman_CountsSharedFindingOnce(t *testing.T) {
	const files = 64
	root := t.TempDir()
	for i := range files {
		// Distinct content per file so each is its own blob; the secret is shared.
		content := fmt.Sprintf("file %d\n%s", i, locTestSecret)
		require.NoError(t, os.WriteFile(filepath.Join(root, fmt.Sprintf("f%02d.txt", i)), []byte(content), 0o644))
	}

	out, err := enumHumanForTest(t, root, nil)
	require.NoError(t, err)

	want := fmt.Sprintf("filesystem scan complete: %d matches, 1 findings\n", files)
	assert.Contains(t, out, want, "summary line:\n%s", out)
}
