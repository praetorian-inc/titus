package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatch(t *testing.T) {
	blobID := ComputeBlobID([]byte("test content"))

	match := Match{
		BlobID:       blobID,
		StructuralID: "structural_id_123",
		RuleID:       "np.aws.1",
		RuleName:     "AWS API Key",
		Location: Location{
			Offset: OffsetSpan{Start: 10, End: 30},
			Source: SourceSpan{
				Start: SourcePoint{Line: 1, Column: 10},
				End:   SourcePoint{Line: 1, Column: 30},
			},
		},
		Groups: [][]byte{[]byte("AKIAIOSFODNN7EXAMPLE")},
		Snippet: Snippet{
			Before:   []byte("aws_access_key="),
			Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
			After:    []byte("\n"),
		},
	}

	assert.Equal(t, blobID, match.BlobID)
	assert.Equal(t, "structural_id_123", match.StructuralID)
	assert.Equal(t, "np.aws.1", match.RuleID)
	assert.Equal(t, "AWS API Key", match.RuleName)
	assert.Equal(t, int64(10), match.Location.Offset.Start)
	assert.Len(t, match.Groups, 1)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", string(match.Groups[0]))
}

func TestMatch_ComputeStructuralID(t *testing.T) {
	blobID := ComputeBlobID([]byte("test content"))

	match := Match{
		BlobID:   blobID,
		RuleID:   "np.aws.1",
		RuleName: "AWS API Key",
		Location: Location{
			Offset: OffsetSpan{Start: 10, End: 30},
		},
	}

	ruleStructuralID := "rule_struct_id_456"
	structuralID := match.ComputeStructuralID(ruleStructuralID)

	// StructuralID should be SHA-1(rule_structural_id + '\0' + blob_id + '\0' + start + '\0' + end)
	assert.NotEmpty(t, structuralID)
	assert.Len(t, structuralID, 40) // SHA-1 hex is 40 chars

	// Same inputs should produce same ID
	match2 := Match{
		BlobID: blobID,
		Location: Location{
			Offset: OffsetSpan{Start: 10, End: 30},
		},
	}
	structuralID2 := match2.ComputeStructuralID(ruleStructuralID)
	assert.Equal(t, structuralID, structuralID2)

	// Different inputs should produce different IDs
	match3 := Match{
		BlobID: blobID,
		Location: Location{
			Offset: OffsetSpan{Start: 11, End: 30}, // Different start
		},
	}
	structuralID3 := match3.ComputeStructuralID(ruleStructuralID)
	assert.NotEqual(t, structuralID, structuralID3)
}

func TestMatch_EmptyGroups(t *testing.T) {
	blobID := ComputeBlobID([]byte("test"))

	match := Match{
		BlobID:   blobID,
		RuleID:   "np.test.1",
		RuleName: "Test Rule",
		Location: Location{
			Offset: OffsetSpan{Start: 0, End: 4},
		},
		Groups:  [][]byte{}, // Empty groups
		Snippet: Snippet{Matching: []byte("test")},
	}

	require.NotNil(t, match.Groups)
	assert.Len(t, match.Groups, 0)
}

func TestMatch_NilGroups(t *testing.T) {
	blobID := ComputeBlobID([]byte("test"))

	match := Match{
		BlobID:   blobID,
		RuleID:   "np.test.1",
		RuleName: "Test Rule",
		Location: Location{
			Offset: OffsetSpan{Start: 0, End: 4},
		},
		Groups:  nil, // Nil groups
		Snippet: Snippet{Matching: []byte("test")},
	}

	assert.Nil(t, match.Groups)
}

func TestMatch_ValidationResult(t *testing.T) {
	match := &Match{
		RuleID:   "np.aws.6",
		RuleName: "AWS API Credentials",
	}

	// Initially nil
	assert.Nil(t, match.ValidationResult)

	// Can be set
	match.ValidationResult = NewValidationResult(StatusValid, 1.0, "valid")
	assert.NotNil(t, match.ValidationResult)
	assert.Equal(t, StatusValid, match.ValidationResult.Status)
}

func TestMatch_JSON_WithValidation(t *testing.T) {
	match := &Match{
		RuleID:           "np.aws.6",
		RuleName:         "AWS API Credentials",
		ValidationResult: NewValidationResult(StatusValid, 1.0, "active credentials"),
	}

	data, err := json.Marshal(match)
	assert.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	// Validation result should be present
	vr, ok := decoded["validation_result"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "valid", vr["status"])
}

func TestMatch_JSON_WithoutValidation(t *testing.T) {
	match := &Match{
		RuleID:   "np.aws.6",
		RuleName: "AWS API Credentials",
		// ValidationResult is nil
	}

	data, err := json.Marshal(match)
	assert.NoError(t, err)

	// validation_result should not be in JSON (omitempty)
	assert.NotContains(t, string(data), "validation_result")
}
