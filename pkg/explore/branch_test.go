package explore

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

func branchLocationLines(t *testing.T, occs ...types.Occurrence) []string {
	t.Helper()
	_, body := locationBlock(t, plainLines(matchWith(12, occs...), nil, 500))
	return body
}

// CASE-EXPLORE-1: the Explore location line shows the branch after the commit
// and the date.
func TestRenderLocations_CASE_EXPLORE_1_ShowsBranch(t *testing.T) {
	o := occAPI1
	o.Branch = "feature/login"
	assert.Equal(t,
		[]string{"    github.com/acme/api  config/a.yml:12  7d0e815  2026-06-15  branch feature/login"},
		branchLocationLines(t, o))
}

// CASE-OMIT-EXPLORE-1: no branch resolved, no segment: the line is the one
// Explore showed before this change, with no empty or placeholder branch.
func TestRenderLocations_CASE_OMIT_EXPLORE_1_NoBranchNoSegment(t *testing.T) {
	lines := branchLocationLines(t, occAPI1)
	assert.Equal(t, []string{"    github.com/acme/api  config/a.yml:12  7d0e815  2026-06-15"}, lines)
	for _, l := range lines {
		assert.NotContains(t, l, "branch")
	}
}

// Each location carries its own branch; a working-tree location shows none.
func TestRenderLocations_BranchPerLocation(t *testing.T) {
	a := occAPI1
	a.Branch = "main"
	b := occAPI2
	b.Branch = "release/1.0"
	wt := types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "x.env", WorkingTree: true,
		AbsolutePath: "/home/u/api/x.env", Branch: "main", HostRecorded: true}
	got := branchLocationLines(t, a, b, wt)
	require.Len(t, got, 3)
	assert.Contains(t, got[0], "  branch main")
	assert.Contains(t, got[1], "  branch release/1.0")
	assert.Equal(t, "    github.com/acme/api  x.env:12  working tree", got[2])
}

// The Explore line is the shared formatter's line: a hostile branch name is
// sanitized in the pane, never written raw.
func TestRenderLocations_BranchIsSanitized(t *testing.T) {
	o := occAPI1
	o.CommitDate = time.Time{}
	o.Branch = "x‮\x1b[31my"
	got := branchLocationLines(t, o)
	require.Len(t, got, 1)
	assert.NotContains(t, got[0], "\x1b")
	assert.NotContains(t, got[0], "‮")
	assert.True(t, strings.HasSuffix(got[0], `branch x\u{202e}\x1b[31my`), got[0])
}
