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

// truncatedAt marks which of the five fixture matches have a truncated
// location list: one printed in full (index 1) and one past fullMatches
// (index 4), each followed by an untruncated match where one exists.
var truncatedAt = []bool{false, true, false, false, true}

const truncCommit = "7d0e8150aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// truncFixture builds five matches (reportFixture), each in its own blob
// with two git locations. Every blob also gets a provenance row that covers
// its first location, so the row adds no line; the row carries truncated[i].
func truncFixture(t *testing.T, truncated []bool) (store.Store, []*types.Finding, []*types.Match, map[string]*types.Rule) {
	t.Helper()
	locs := make([][]types.Occurrence, len(truncated))
	for i := range truncated {
		for _, name := range []string{"a.yml", "b.yml"} {
			locs[i] = append(locs[i], types.Occurrence{
				Kind: "git", Repository: "github.com/acme/api", Path: fmt.Sprintf("m%d/%s", i, name),
				Commit: truncCommit, CommitDate: reportCommitDate, HostRecorded: true,
			})
		}
	}
	s, findings, matches, ruleMap := reportFixture(t, locs...)
	for i, m := range matches {
		require.NoError(t, s.AddProvenance(m.BlobID, types.GitProvenance{
			RepoPath:           "github.com/acme/api",
			BlobPath:           fmt.Sprintf("m%d/a.yml", i),
			Commit:             &types.CommitMetadata{CommitID: truncCommit, CommitterTimestamp: reportCommitDate},
			LocationsTruncated: truncated[i],
		}))
	}
	return s, findings, matches, ruleMap
}

// ENG-9178: in the human report the marker follows the truncated match's
// location list exactly once, on both the full path and the compact path
// past fullMatches, and nowhere else.
func TestReportHuman_LocationsTruncatedMarkerFollowsList(t *testing.T) {
	s, findings, matches, ruleMap := truncFixture(t, make([]bool, len(truncatedAt)))
	base := humanLocationLines(renderHuman(t, s, findings, matches, ruleMap))
	require.Len(t, base, 2*len(truncatedAt), "fixture: two lines per match, provenance covered")

	s, findings, matches, ruleMap = truncFixture(t, truncatedAt)
	out := renderHuman(t, s, findings, matches, ruleMap)
	var want []string
	for i, trunc := range truncatedAt {
		want = append(want, base[2*i:2*i+2]...)
		if trunc {
			want = append(want, "    "+types.LocationsTruncatedNotice)
		}
	}
	assert.Equal(t, want, humanLocationLines(out))
	assert.Equal(t, 2, strings.Count(out, types.LocationsTruncatedNotice))
}

// The report JSON carries "locations_truncated": true only on the truncated
// matches; on the others the key is absent.
func TestReportJSON_LocationsTruncatedOnlyOnTruncatedMatches(t *testing.T) {
	var out []struct {
		Matches []map[string]json.RawMessage `json:"Matches"`
	}
	s, findings, matches, ruleMap := truncFixture(t, truncatedAt)
	require.NoError(t, json.Unmarshal(renderJSON(t, s, findings, matches, ruleMap), &out))
	require.Len(t, out, 1)
	assertTruncatedKey(t, out[0].Matches)
}

// The scan JSON (outputMatches) follows the same rule.
func TestScanJSON_LocationsTruncatedOnlyOnTruncatedMatches(t *testing.T) {
	s, _, matches, _ := truncFixture(t, truncatedAt)
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, outputMatches(cmd, s, matches))
	var out []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	assertTruncatedKey(t, out)
}

func assertTruncatedKey(t *testing.T, ms []map[string]json.RawMessage) {
	t.Helper()
	require.Len(t, ms, len(truncatedAt))
	for i, m := range ms {
		v, present := m["locations_truncated"]
		if !truncatedAt[i] {
			assert.False(t, present, "match %d: key omitted when false", i)
			continue
		}
		assert.JSONEq(t, "true", string(v), "match %d", i)
	}
}

// In SARIF only the last result of each truncated match carries
// properties.locationsTruncated; its other result, and every result of the
// untruncated matches before and after it, do not.
func TestReportSARIF_LocationsTruncatedOnLastResultOfMatch(t *testing.T) {
	var rep struct {
		Runs []struct {
			Results []struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	s, findings, matches, ruleMap := truncFixture(t, truncatedAt)
	require.NoError(t, json.Unmarshal(renderSARIF(t, s, findings, matches, ruleMap), &rep))
	require.Len(t, rep.Runs, 1)

	var got, want []bool
	for _, r := range rep.Runs[0].Results {
		v, present := r.Properties["locationsTruncated"]
		if present {
			require.JSONEq(t, "true", string(v))
		}
		got = append(got, present)
	}
	for _, trunc := range truncatedAt {
		want = append(want, false, trunc)
	}
	assert.Equal(t, want, got)
}
