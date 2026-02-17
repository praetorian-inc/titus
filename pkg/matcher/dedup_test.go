package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestNewDeduplicator(t *testing.T) {
	d := NewDeduplicator()
	assert.NotNil(t, d)
	assert.NotNil(t, d.seen)
}

func TestDeduplicator_FirstMatchNotDuplicate(t *testing.T) {
	d := NewDeduplicator()

	m := &types.Match{
		StructuralID: "abc123",
	}

	// First occurrence should not be a duplicate
	assert.False(t, d.IsDuplicate(m))
}

func TestDeduplicator_AddMarksSeen(t *testing.T) {
	d := NewDeduplicator()

	m := &types.Match{
		StructuralID: "abc123",
	}

	// Add the match
	d.Add(m)

	// Now it should be marked as duplicate
	assert.True(t, d.IsDuplicate(m))
}

func TestDeduplicator_DifferentMatchesNotDuplicates(t *testing.T) {
	d := NewDeduplicator()

	m1 := &types.Match{
		StructuralID: "abc123",
	}
	m2 := &types.Match{
		StructuralID: "def456",
	}

	d.Add(m1)

	// Different structural ID should not be duplicate
	assert.False(t, d.IsDuplicate(m2))
}

func TestDeduplicator_MultipleAdds(t *testing.T) {
	d := NewDeduplicator()

	m1 := &types.Match{StructuralID: "abc123"}
	m2 := &types.Match{StructuralID: "def456"}
	m3 := &types.Match{StructuralID: "abc123"} // duplicate of m1

	// Add first two
	d.Add(m1)
	d.Add(m2)

	// Check duplicates
	assert.True(t, d.IsDuplicate(m1))
	assert.True(t, d.IsDuplicate(m2))
	assert.True(t, d.IsDuplicate(m3)) // same as m1
}

func TestDeduplicator_EmptyStructuralID(t *testing.T) {
	d := NewDeduplicator()

	m := &types.Match{
		StructuralID: "",
	}

	// Empty structural ID should work (edge case)
	assert.False(t, d.IsDuplicate(m))
	d.Add(m)
	assert.True(t, d.IsDuplicate(m))
}

func TestDeduplicator_Reset(t *testing.T) {
	d := NewDeduplicator()
	m1 := &types.Match{StructuralID: "abc123"}
	m2 := &types.Match{StructuralID: "def456"}

	// Add matches and verify they're tracked
	d.Add(m1)
	d.Add(m2)
	assert.True(t, d.IsDuplicate(m1))
	assert.True(t, d.IsDuplicate(m2))

	// Reset should clear the seen map
	d.Reset()

	assert.False(t, d.IsDuplicate(m1), "Reset should clear seen map")
	assert.False(t, d.IsDuplicate(m2), "Reset should clear seen map")

	// Verify reuse works after reset
	d.Add(m1)
	assert.True(t, d.IsDuplicate(m1), "Should work after reset")
}

func TestDeduplicator_ContentMode(t *testing.T) {
	d := NewContentDeduplicator()

	// Same content, different locations
	m1 := &types.Match{
		RuleID:       "test-rule",
		StructuralID: "loc1",
		Snippet:      types.Snippet{Matching: []byte("secret123")},
	}
	m2 := &types.Match{
		RuleID:       "test-rule",
		StructuralID: "loc2", // Different location
		Snippet:      types.Snippet{Matching: []byte("secret123")}, // Same content
	}

	assert.False(t, d.IsDuplicate(m1))
	d.Add(m1)
	assert.True(t, d.IsDuplicate(m1))

	// m2 has same content, should be duplicate
	assert.True(t, d.IsDuplicate(m2), "Same content should be duplicate in content mode")
}

func TestDeduplicator_LocationMode(t *testing.T) {
	d := NewDeduplicator() // Location mode by default

	// Same content, different locations
	m1 := &types.Match{
		RuleID:       "test-rule",
		StructuralID: "loc1",
		Snippet:      types.Snippet{Matching: []byte("secret123")},
	}
	m2 := &types.Match{
		RuleID:       "test-rule",
		StructuralID: "loc2", // Different location
		Snippet:      types.Snippet{Matching: []byte("secret123")}, // Same content
	}

	assert.False(t, d.IsDuplicate(m1))
	d.Add(m1)

	// m2 has different structural ID, should NOT be duplicate in location mode
	assert.False(t, d.IsDuplicate(m2), "Different location should not be duplicate in location mode")
}

func TestDeduplicator_SetMode(t *testing.T) {
	d := NewDeduplicator()
	assert.Equal(t, DedupeByLocation, d.mode)

	d.SetMode(DedupeByContent)
	assert.Equal(t, DedupeByContent, d.mode)
}

func TestDeduplicator_ContentMode_UsesGroups(t *testing.T) {
	d := NewContentDeduplicator()

	// Same secret value in capture groups, but different surrounding context
	// This simulates: "API_KEY=secret123" vs "export API_KEY=secret123"
	// The capture group extracts just "secret123" in both cases
	m1 := &types.Match{
		RuleID:       "test-rule",
		StructuralID: "loc1",
		Groups:       [][]byte{[]byte("secret123")}, // Capture group contains actual secret
		Snippet: types.Snippet{
			Matching: []byte("API_KEY=secret123"), // Context: env var assignment
		},
	}
	m2 := &types.Match{
		RuleID:       "test-rule",
		StructuralID: "loc2",
		Groups:       [][]byte{[]byte("secret123")}, // Same captured secret
		Snippet: types.Snippet{
			Matching: []byte("export API_KEY=secret123"), // Different context: export statement
		},
	}

	// First match is not duplicate
	assert.False(t, d.IsDuplicate(m1))
	d.Add(m1)
	assert.True(t, d.IsDuplicate(m1))

	// m2 has same Groups (actual secret), should be duplicate
	// even though Snippet.Matching differs (different context)
	assert.True(t, d.IsDuplicate(m2), "Same secret value in Groups should be duplicate in content mode")
}
