package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeFindingID(t *testing.T) {
	ruleStructuralID := "rule_abc123"
	groups := [][]byte{
		[]byte("group1"),
		[]byte("group2"),
	}

	id := ComputeFindingID(ruleStructuralID, groups)

	// Should be SHA-1 hex (40 chars)
	assert.Len(t, id, 40)
	assert.NotEmpty(t, id)

	// Same inputs should produce same ID
	id2 := ComputeFindingID(ruleStructuralID, groups)
	assert.Equal(t, id, id2)

	// Different groups should produce different ID
	groups3 := [][]byte{
		[]byte("group1"),
		[]byte("different"),
	}
	id3 := ComputeFindingID(ruleStructuralID, groups3)
	assert.NotEqual(t, id, id3)

	// Different rule structural ID should produce different ID
	id4 := ComputeFindingID("different_rule", groups)
	assert.NotEqual(t, id, id4)
}

func TestComputeFindingID_EmptyGroups(t *testing.T) {
	ruleStructuralID := "rule_abc123"
	groups := [][]byte{}

	id := ComputeFindingID(ruleStructuralID, groups)

	assert.Len(t, id, 40)
	assert.NotEmpty(t, id)
}

func TestComputeFindingID_NilGroups(t *testing.T) {
	ruleStructuralID := "rule_abc123"
	var groups [][]byte = nil

	id := ComputeFindingID(ruleStructuralID, groups)

	assert.Len(t, id, 40)
	assert.NotEmpty(t, id)
}

func TestFinding(t *testing.T) {
	blobID := ComputeBlobID([]byte("test content"))

	match1 := &Match{
		BlobID:   blobID,
		RuleID:   "np.aws.1",
		RuleName: "AWS API Key",
		Location: Location{
			Offset: OffsetSpan{Start: 10, End: 30},
		},
		Groups: [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
	}

	match2 := &Match{
		BlobID:   blobID,
		RuleID:   "np.aws.1",
		RuleName: "AWS API Key",
		Location: Location{
			Offset: OffsetSpan{Start: 50, End: 70},
		},
		Groups: [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
	}

	finding := Finding{
		ID:       "finding_id_123",
		RuleID:   "np.aws.1",
		Groups:   [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
		Matches:  []*Match{match1, match2},
	}

	assert.Equal(t, "finding_id_123", finding.ID)
	assert.Equal(t, "np.aws.1", finding.RuleID)
	assert.Len(t, finding.Groups, 1)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", string(finding.Groups[0]))
	require.Len(t, finding.Matches, 2)
	assert.Equal(t, match1, finding.Matches[0])
	assert.Equal(t, match2, finding.Matches[1])
}

func TestFinding_NoMatches(t *testing.T) {
	finding := Finding{
		ID:      "finding_id_123",
		RuleID:  "np.test.1",
		Groups:  [][]byte{[]byte("test")},
		Matches: []*Match{},
	}

	require.NotNil(t, finding.Matches)
	assert.Len(t, finding.Matches, 0)
}

func TestFinding_NilMatches(t *testing.T) {
	finding := Finding{
		ID:      "finding_id_123",
		RuleID:  "np.test.1",
		Groups:  [][]byte{[]byte("test")},
		Matches: nil,
	}

	assert.Nil(t, finding.Matches)
}
