//go:build !wasm

package matcher

import (
	"bytes"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// TestMatchWithBlobIDAndOptions_LargeFile tests that files >5MB are chunked correctly
func TestMatchWithBlobIDAndOptions_LargeFile(t *testing.T) {
	// Create a matcher with a simple pattern
	rules := []*types.Rule{
		{
			ID:      "test.secret",
			Name:    "Test Secret",
			Pattern: `SECRET[0-9]{4}`,
		},
	}

	matcher, err := NewPortableRegexp(rules, 0)
	if err != nil {
		t.Fatalf("Failed to create matcher: %v", err)
	}

	// Create a 6MB file with secrets scattered throughout
	// Each line is ~100 bytes, so we need ~60,000 lines for 6MB
	var content bytes.Buffer
	secretPositions := []int{1000, 30000, 59000} // Line numbers where secrets appear

	for i := 0; i < 60000; i++ {
		line := strings.Repeat("x", 90) // 90 bytes of content
		if contains(secretPositions, i) {
			line = "SECRET" + strings.Repeat("0", 4) + strings.Repeat("x", 80) // Add secret to this line
		}
		content.WriteString(line + "\n")
	}

	if content.Len() < 5*1024*1024 {
		t.Fatalf("Test content is too small: %d bytes, need >5MB", content.Len())
	}

	// Scan the content
	blobID := types.ComputeBlobID(content.Bytes())
	result, err := matcher.MatchWithBlobIDAndOptions(content.Bytes(), blobID, DefaultOptions())
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	// Should find all secrets
	if len(result.Matches) != len(secretPositions) {
		t.Errorf("Expected %d matches, got %d", len(secretPositions), len(result.Matches))
	}

	// All matches should have valid offsets
	for i, match := range result.Matches {
		if match.Location.Offset.Start < 0 {
			t.Errorf("Match %d has negative start offset: %d", i, match.Location.Offset.Start)
		}
		if match.Location.Offset.End <= match.Location.Offset.Start {
			t.Errorf("Match %d has invalid offset range: [%d, %d]", i, match.Location.Offset.Start, match.Location.Offset.End)
		}
		if match.Location.Offset.End > int64(content.Len()) {
			t.Errorf("Match %d end offset %d exceeds content length %d", i, match.Location.Offset.End, content.Len())
		}
	}
}

// TestMatchWithBlobIDAndOptions_SecretAtChunkBoundary tests detection of secrets near chunk boundaries
func TestMatchWithBlobIDAndOptions_SecretAtChunkBoundary(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test.secret",
			Name:    "Test Secret",
			Pattern: `API_KEY[0-9]{10}`,
		},
	}

	matcher, err := NewPortableRegexp(rules, 0)
	if err != nil {
		t.Fatalf("Failed to create matcher: %v", err)
	}

	// Create content where secret appears right around the 5MB boundary
	// This tests that chunking overlap catches secrets at boundaries
	var content bytes.Buffer

	// Write ~4.9MB of padding
	paddingSize := 4*1024*1024 + 900*1024 // 4.9MB
	for content.Len() < paddingSize {
		content.WriteString(strings.Repeat("x", 100) + "\n")
	}

	// Write secret right near the 5MB boundary
	content.WriteString("API_KEY1234567890\n")

	// Write more content to exceed 5MB
	for content.Len() < 5*1024*1024+100*1024 {
		content.WriteString(strings.Repeat("y", 100) + "\n")
	}

	blobID := types.ComputeBlobID(content.Bytes())
	result, err := matcher.MatchWithBlobIDAndOptions(content.Bytes(), blobID, DefaultOptions())
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	// Should find the secret even though it's at the boundary
	if len(result.Matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(result.Matches))
	}
}

// TestMatchWithBlobIDAndOptions_NoDuplicatesFromOverlap tests that overlap doesn't create duplicates
func TestMatchWithBlobIDAndOptions_NoDuplicatesFromOverlap(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test.secret",
			Name:    "Test Secret",
			Pattern: `TOKEN[0-9]{8}`,
		},
	}

	matcher, err := NewPortableRegexp(rules, 0)
	if err != nil {
		t.Fatalf("Failed to create matcher: %v", err)
	}

	// Create content with a secret in the overlap region
	// The overlap is 10 lines by default, so put secret in that zone
	var content bytes.Buffer

	// Write enough to trigger chunking
	// Each line ~100 bytes, need >50,000 lines for 5MB
	for i := 0; i < 52000; i++ {
		line := strings.Repeat("x", 90)

		// Put a secret in the overlap zone (will appear in chunk 1 end and chunk 2 start)
		if i == 50990 { // Near first chunk boundary
			line = "TOKEN12345678" + strings.Repeat("x", 80)
		}

		content.WriteString(line + "\n")
	}

	blobID := types.ComputeBlobID(content.Bytes())
	result, err := matcher.MatchWithBlobIDAndOptions(content.Bytes(), blobID, DefaultOptions())
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	// Should find exactly 1 match (deduplication should prevent duplicates from overlap)
	if len(result.Matches) != 1 {
		t.Errorf("Expected 1 match (deduplicated), got %d", len(result.Matches))
	}
}

// TestMatchWithBlobIDAndOptions_SmallFileUnaffected tests that small files (<5MB) work as before
func TestMatchWithBlobIDAndOptions_SmallFileUnaffected(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test.secret",
			Name:    "Test Secret",
			Pattern: `PASSWORD[0-9]{6}`,
		},
	}

	matcher, err := NewPortableRegexp(rules, 0)
	if err != nil {
		t.Fatalf("Failed to create matcher: %v", err)
	}

	// Small content (< 5MB)
	content := []byte("This is a test file\nPASSWORD123456\nMore content here\n")

	blobID := types.ComputeBlobID(content)
	result, err := matcher.MatchWithBlobIDAndOptions(content, blobID, DefaultOptions())
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}

	if len(result.Matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(result.Matches))
	}

	// Verify offset is correct
	if result.Matches[0].Location.Offset.Start < 0 {
		t.Errorf("Invalid offset: %d", result.Matches[0].Location.Offset.Start)
	}
}

// Helper function
func contains(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
