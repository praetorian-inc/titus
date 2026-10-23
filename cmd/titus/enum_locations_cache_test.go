package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// provCountingStore counts GetAllProvenance calls per blob.
type provCountingStore struct {
	store.Store
	calls map[types.BlobID]int
}

func (c *provCountingStore) GetAllProvenance(id types.BlobID) ([]types.Provenance, error) {
	c.calls[id]++
	return c.Store.GetAllProvenance(id)
}

// Two findings whose matches share one truncated blob: enum human output
// loads that blob's locations once, and both findings still list its
// location and the truncation marker from the shared result.
func TestEnumHuman_SharedBlobLoadedOnce(t *testing.T) {
	mem := store.NewMemory()
	r := &types.Rule{ID: "np.test.1", Name: "Test Rule", Pattern: "tok_.*"}
	r.StructuralID = r.ComputeStructuralID()
	blob := types.ComputeBlobID([]byte("tok_one tok_two"))
	require.NoError(t, mem.AddOccurrences(blob, []types.Occurrence{{Kind: "file", Path: "shared.env"}}))
	require.NoError(t, mem.AddProvenance(blob, types.GitProvenance{RepoPath: "r", BlobPath: "prov.env", LocationsTruncated: true}))

	var findings []*types.Finding
	for i, g := range []string{"tok_one", "tok_two"} {
		groups := [][]byte{[]byte(g)}
		f := &types.Finding{ID: types.ComputeFindingID(r.StructuralID, groups), RuleID: r.ID, Groups: groups}
		require.NoError(t, mem.AddFinding(f))
		require.NoError(t, mem.AddMatch(&types.Match{
			StructuralID: "sm-" + g, RuleID: r.ID, BlobID: blob, Groups: groups,
			Location: types.Location{Source: types.SourceSpan{Start: types.SourcePoint{Line: i + 1}}},
		}))
		findings = append(findings, f)
	}

	s := &provCountingStore{Store: mem, calls: map[types.BlobID]int{}}
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	require.NoError(t, outputFindings(cmd, s, map[string]*types.Rule{r.ID: r}, findings))

	assert.Equal(t, 1, s.calls[blob], "blob locations loaded once:\n%s", out.String())
	assert.Equal(t, 2, strings.Count(out.String(), "shared.env"), "location under each finding:\n%s", out.String())
	assert.Equal(t, 2, strings.Count(out.String(), types.LocationsTruncatedNotice), "marker under each finding:\n%s", out.String())
}
