package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const branchTestCommit = "0123456789abcdef0123456789abcdef01234567"

func branchOcc(branch string) Occurrence {
	return Occurrence{
		Kind: "git", Repository: "github.com/acme/api", Path: "config.yml",
		Commit: branchTestCommit, CommitDate: jun15, Branch: branch, HostRecorded: true,
	}
}

// FormatLine golden strings. The branch follows the commit and the date.
func TestFormatLine_Branch(t *testing.T) {
	cases := []struct {
		name string
		occ  Occurrence
		want string
	}{
		{"CASE-REPORT-1 commit, date and branch",
			branchOcc("feature/login"),
			"github.com/acme/api  config.yml:3  0123456  2026-06-15  branch feature/login"},
		{"commit and date without branch is the unchanged line",
			branchOcc(""),
			"github.com/acme/api  config.yml:3  0123456  2026-06-15"},
		{"CASE-OMIT-REPORT-1 no empty or placeholder segment",
			branchOcc(""),
			"github.com/acme/api  config.yml:3  0123456  2026-06-15"},
		{"commit with branch and no date",
			Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: branchTestCommit, Branch: "main", HostRecorded: true},
			"github.com/acme/api  config.yml:3  0123456  branch main"},
		{"working tree shows no branch even if one is set",
			Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", WorkingTree: true, Branch: "main", HostRecorded: true},
			"github.com/acme/api  config.yml:3  working tree"},
		{"legacy host-not-recorded row keeps its marker after the branch",
			Occurrence{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", Commit: branchTestCommit, CommitDate: jun15, Branch: "main"},
			"github.com/acme/api  config.yml:3  0123456  2026-06-15  branch main  host not recorded"},
		{"escape and newline in a branch name are sanitized",
			branchOcc("a\x1b[31mb\nc"),
			`github.com/acme/api  config.yml:3  0123456  2026-06-15  branch a\x1b[31mb\x0ac`},
		{"bidi override in a branch name is sanitized",
			branchOcc("x\U0000202ey"),
			`github.com/acme/api  config.yml:3  0123456  2026-06-15  branch x\u{202e}y`},
		{"a branch name with legal punctuation and unicode is verbatim",
			branchOcc("feat/ünï-日本"),
			"github.com/acme/api  config.yml:3  0123456  2026-06-15  branch feat/ünï-日本"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, FormatLine(c.occ, 3, ""))
		})
	}
}

// A duplicate row never erases a resolved branch, whichever comes first.
func TestSortedUnique_KeepsNonEmptyBranch(t *testing.T) {
	for name, rows := range map[string][]Occurrence{
		"resolved first": {branchOcc("main"), branchOcc("")},
		"resolved last":  {branchOcc(""), branchOcc("main")},
		"both resolved":  {branchOcc("main"), branchOcc("main")},
	} {
		t.Run(name, func(t *testing.T) {
			got := sortedUnique(rows)
			require.Len(t, got, 1)
			assert.Equal(t, "main", got[0].Branch)
		})
	}
	t.Run("none resolved stays empty", func(t *testing.T) {
		got := sortedUnique([]Occurrence{branchOcc(""), branchOcc("")})
		require.Len(t, got, 1)
		assert.Equal(t, "", got[0].Branch)
	})
	t.Run("distinct identities stay distinct and keep their own branch", func(t *testing.T) {
		a, b := branchOcc("main"), branchOcc("other")
		b.Path = "other.yml"
		got := sortedUnique([]Occurrence{b, a})
		require.Len(t, got, 2)
		assert.Equal(t, "main", got[0].Branch)
		assert.Equal(t, "other", got[1].Branch)
	})
}

// The git provenance record: Branch rides on CommitMetadata, copied to every
// flattened Occurrence of a committed location, never to a working-tree one.
func TestGitProvenance_BranchFlowsToOccurrences(t *testing.T) {
	p := GitProvenance{
		RepoPath: "github.com/acme/api", BlobPath: "config.yml",
		Commit: &CommitMetadata{CommitID: branchTestCommit, Branch: "feature/login", CommitterTimestamp: jun15},
		Locations: []GitLocation{
			{Path: "config.yml", Commit: &CommitMetadata{CommitID: branchTestCommit, Branch: "feature/login", CommitterTimestamp: jun15}},
			{Path: "backup/config.yml", WorkingTree: true},
			{Path: "old.yml", Commit: &CommitMetadata{CommitID: "89abcdef0123456789abcdef0123456789abcdef"}},
		},
		RemoteIdentity: true,
	}
	byPath := map[string]Occurrence{}
	for _, o := range OccurrencesOf(p) {
		byPath[o.Path] = o
	}
	require.Len(t, byPath, 3)
	assert.Equal(t, "feature/login", byPath["config.yml"].Branch)
	assert.Equal(t, "", byPath["backup/config.yml"].Branch)
	assert.Equal(t, "", byPath["old.yml"].Branch, "an unresolved commit has no branch, not a neighbour's")
}

// The stored provenance JSON gains "Branch" only when one was resolved, so an
// existing datastore row and a scan with no branch serialize as before.
func TestCommitMetadata_BranchJSONOmitEmpty(t *testing.T) {
	without, err := json.Marshal(CommitMetadata{CommitID: branchTestCommit})
	require.NoError(t, err)
	assert.NotContains(t, string(without), "Branch")

	with, err := json.Marshal(CommitMetadata{CommitID: branchTestCommit, Branch: "main"})
	require.NoError(t, err)
	assert.Contains(t, string(with), `"Branch":"main"`)

	var old CommitMetadata
	require.NoError(t, json.Unmarshal(without, &old))
	assert.Equal(t, "", old.Branch)
}
