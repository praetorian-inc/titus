package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// locCountingStore counts, per blob, the two reads that load a blob's
// locations: GetOccurrences and GetAllProvenance.
type locCountingStore struct {
	store.Store
	occCalls, provCalls map[types.BlobID]int
}

func newLocCountingStore(s store.Store) *locCountingStore {
	return &locCountingStore{Store: s, occCalls: map[types.BlobID]int{}, provCalls: map[types.BlobID]int{}}
}

func (c *locCountingStore) GetOccurrences(id types.BlobID) ([]types.Occurrence, error) {
	c.occCalls[id]++
	return c.Store.GetOccurrences(id)
}

func (c *locCountingStore) GetAllProvenance(id types.BlobID) ([]types.Provenance, error) {
	c.provCalls[id]++
	return c.Store.GetAllProvenance(id)
}

// sharedBlobFixture stores one finding with n matches on lines 1..n of one
// blob that has two locations.
func sharedBlobFixture(t *testing.T, n int) (store.Store, types.BlobID, []*types.Finding, []*types.Match, map[string]*types.Rule) {
	t.Helper()
	mem := store.NewMemory()
	r := &types.Rule{ID: locTestRuleID, Name: "Synthetic Rule 1", Pattern: "synthetic_1_.*"}
	r.StructuralID = r.ComputeStructuralID()
	blob := types.ComputeBlobID([]byte(locTestSecret))
	require.NoError(t, mem.AddOccurrences(blob, []types.Occurrence{
		{Kind: "file", Path: "a/config.yml"},
		{Kind: "file", Path: "b/config.yml"},
	}))
	groups := [][]byte{[]byte("synthetic_1_AbCd1234")}
	f := &types.Finding{ID: types.ComputeFindingID(r.StructuralID, groups), RuleID: r.ID, Groups: groups}
	require.NoError(t, mem.AddFinding(f))
	var matches []*types.Match
	for i := range n {
		m := &types.Match{
			StructuralID: fmt.Sprintf("sm-%d", i), FindingID: f.ID, RuleID: r.ID, BlobID: blob, Groups: groups,
			Location: types.Location{Source: types.SourceSpan{Start: types.SourcePoint{Line: i + 1}}},
			Snippet:  types.Snippet{Matching: groups[0]},
		}
		require.NoError(t, mem.AddMatch(m))
		matches = append(matches, m)
	}
	return mem, blob, []*types.Finding{f}, matches, map[string]*types.Rule{r.ID: r}
}

// ENG-9178: `titus report` loads a blob's locations once, not once per
// match, and still prints them under every match. Five matches cover both
// the full and the location-only rendering (fullMatches is 3).
func TestOutputReportHuman_SharedBlobLocationsLoadedOnce(t *testing.T) {
	mem, blob, findings, matches, ruleMap := sharedBlobFixture(t, 5)
	s := newLocCountingStore(mem)

	origColor := reportColor
	t.Cleanup(func() { reportColor = origColor })
	reportColor = "never"
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	require.NoError(t, outputReportHuman(cmd, s, findings, matches, ruleMap))

	assert.Equal(t, 1, s.occCalls[blob], "GetOccurrences calls for the shared blob")
	assert.Equal(t, 1, s.provCalls[blob], "GetAllProvenance calls for the shared blob")
	assert.Equal(t, 5, strings.Count(out.String(), "a/config.yml"), "location under every match:\n%s", out.String())
	assert.Equal(t, 5, strings.Count(out.String(), "b/config.yml"), "location under every match:\n%s", out.String())
}

// The same for `titus scan --format json` (outputMatches).
func TestOutputMatches_SharedBlobLocationsLoadedOnce(t *testing.T) {
	mem, blob, _, matches, _ := sharedBlobFixture(t, 3)
	s := newLocCountingStore(mem)

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	require.NoError(t, outputMatches(cmd, s, matches))

	assert.Equal(t, 1, s.occCalls[blob], "GetOccurrences calls for the shared blob")
	assert.Equal(t, 1, s.provCalls[blob], "GetAllProvenance calls for the shared blob")
	var got []scanJSONMatchForTest
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Len(t, got, 3)
	for _, m := range got {
		assert.Equal(t, []string{"a/config.yml", "b/config.yml"}, locationPaths(m.Locations))
	}
}
