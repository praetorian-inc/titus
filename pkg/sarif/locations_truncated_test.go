package sarif

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resultProperties decodes the report's JSON and returns each result's raw
// properties object (nil when absent).
func resultProperties(t *testing.T, r *Report) []map[string]any {
	t.Helper()
	data, err := r.ToJSON()
	require.NoError(t, err)
	var out struct {
		Runs []struct {
			Results []struct {
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(data, &out))
	require.Len(t, out.Runs, 1)
	props := make([]map[string]any, 0, len(out.Runs[0].Results))
	for _, res := range out.Runs[0].Results {
		props = append(props, res.Properties)
	}
	return props
}

func truncMatch(content string) *types.Match {
	return &types.Match{BlobID: types.ComputeBlobID([]byte(content)), RuleID: "np.t.1", RuleName: "T"}
}

// ENG-9178: MarkLocationsTruncated flags only the result added last, under
// the exact key properties.locationsTruncated; earlier results stay unflagged.
func TestMarkLocationsTruncated_LastResultOnly(t *testing.T) {
	r := NewReport()
	other := truncMatch("other")
	m := truncMatch("x")
	r.AddResultForOccurrence(other, types.Occurrence{Kind: "git", Repository: "a", Path: "o1", HostRecorded: true}, nil)
	r.AddResultForOccurrence(m, types.Occurrence{Kind: "git", Repository: "a", Path: "p1", HostRecorded: true}, nil)
	r.AddResultForOccurrence(m, types.Occurrence{Kind: "git", Repository: "a", Path: "p2", HostRecorded: true}, nil)
	r.MarkLocationsTruncated()

	props := resultProperties(t, r)
	require.Len(t, props, 3)
	for i, p := range props[:2] {
		assert.NotContains(t, p, "locationsTruncated", "result %d", i)
	}
	assert.Equal(t, true, props[2]["locationsTruncated"])
}

// A result without properties gains them; an empty report is left alone.
func TestMarkLocationsTruncated_NoPropertiesYetAndNoResults(t *testing.T) {
	r := NewReport()
	r.MarkLocationsTruncated()
	assert.Empty(t, r.Runs[0].Results)

	r.AddResultWithScore(truncMatch("x"), "blob", nil)
	require.Nil(t, r.Runs[0].Results[0].Properties, "fixture: a nil score gives no properties")
	r.MarkLocationsTruncated()
	assert.Equal(t, true, resultProperties(t, r)[0]["locationsTruncated"])
}
