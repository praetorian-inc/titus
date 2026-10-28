//go:build windows

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On Windows a folder is typed with backslashes while the selector compares
// "/" forms. filepath.ToSlash is the identity elsewhere, so only this build
// can tell a missing normalization from a correct one.
func TestReportSelector_WindowsFolderForms(t *testing.T) {
	inTeam := suLocal("api", `C:\work\team\api`, "src/a.go")
	inTeamx := suLocal("api", `C:\work\teamx\api`, "src/a.go")
	require.Equal(t, `C:\work\team\api\src\a.go`, inTeam.AbsolutePath)
	assert.Equal(t, "C:/work/team/api", absoluteFolder(inTeam))

	t.Run("namespace with backslashes selects the folder, not a sibling prefix", func(t *testing.T) {
		sel, err := newReportSelector(nil, []string{`C:\work\team`}, nil)
		require.NoError(t, err)
		assert.True(t, sel.selects(inTeam))
		assert.False(t, sel.selects(inTeamx))
	})
	t.Run("repo with backslashes selects the exact folder", func(t *testing.T) {
		sel, err := newReportSelector([]string{`C:\work\team\api`}, nil, nil)
		require.NoError(t, err)
		assert.True(t, sel.selects(inTeam))
		assert.False(t, sel.selects(inTeamx))
	})
}
