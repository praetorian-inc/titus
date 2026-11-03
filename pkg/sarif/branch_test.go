package sarif

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/titus/pkg/types"
)

func branchOccurrence(branch string) types.Occurrence {
	return types.Occurrence{
		Kind: "git", Repository: "github.com/acme/api", Path: "config.yml",
		Commit: "0123456789abcdef0123456789abcdef01234567", CommitDate: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		Branch: branch, HostRecorded: true,
	}
}

// properties.branch is a string when a branch was resolved and absent (not
// null, not "") when none was.
func TestAddResultForOccurrence_Branch(t *testing.T) {
	r := NewReport()
	m := truncMatch("x")
	r.AddResultForOccurrence(m, branchOccurrence("feature/login"), nil)
	r.AddResultForOccurrence(m, branchOccurrence(""), nil)
	wt := types.Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "w.yml", WorkingTree: true, HostRecorded: true}
	r.AddResultForOccurrence(m, wt, nil)

	props := resultProperties(t, r)
	require.Len(t, props, 3)
	assert.Equal(t, "feature/login", props[0]["branch"])
	assert.NotContains(t, props[1], "branch", "CASE-OMIT-REPORT-1: no placeholder, no empty string, no null")
	assert.NotContains(t, props[2], "branch")
	// The rest of the properties are the ones the branch did not touch.
	assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", props[0]["commit"])
	assert.Equal(t, "2026-06-15T12:00:00Z", props[0]["commit_date"])
}

// A branch name is kept byte for byte: encoding/json escapes it safely, the
// consumer gets the name git has.
func TestAddResultForOccurrence_BranchVerbatim(t *testing.T) {
	r := NewReport()
	r.AddResultForOccurrence(truncMatch("x"), branchOccurrence("feat/ünï-日本"), nil)
	assert.Equal(t, "feat/ünï-日本", resultProperties(t, r)[0]["branch"])
}
