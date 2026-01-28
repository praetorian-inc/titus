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
