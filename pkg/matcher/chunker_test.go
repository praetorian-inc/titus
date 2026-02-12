package matcher

import (
	"bytes"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestChunkContent_SmallFile(t *testing.T) {
	config := ChunkConfig{
		MaxChunkSize: 5 * 1024 * 1024, // 5MB
		OverlapLines: 10,
	}

	// Small content (< 5MB) should return single chunk
	content := []byte("line1\nline2\nline3\n")
	chunks := ChunkContent(content, config)

	if len(chunks) != 1 {
		t.Errorf("Expected 1 chunk for small file, got %d", len(chunks))
	}

	chunk := chunks[0]
	if !bytes.Equal(chunk.Content, content) {
		t.Errorf("Chunk content mismatch")
	}
	if chunk.StartOffset != 0 {
		t.Errorf("Expected StartOffset 0, got %d", chunk.StartOffset)
	}
	if chunk.EndOffset != len(content) {
		t.Errorf("Expected EndOffset %d, got %d", len(content), chunk.EndOffset)
	}
	if chunk.Index != 0 {
		t.Errorf("Expected Index 0, got %d", chunk.Index)
	}
}

func TestChunkContent_LargeFile(t *testing.T) {
	config := ChunkConfig{
		MaxChunkSize: 100, // Small chunk for testing
		OverlapLines: 2,
	}

	// Create content with ~150 bytes (should split into 2 chunks)
	lines := []string{
		"line1 aaaaaaaaaa", // ~15 bytes + \n
		"line2 bbbbbbbbbb",
		"line3 cccccccccc",
		"line4 dddddddddd",
		"line5 eeeeeeeeee",
		"line6 ffffffffff",
		"line7 gggggggggg",
		"line8 hhhhhhhhhh",
		"line9 iiiiiiiiii",
		"line10 jjjjjjjjjj",
	}
	content := []byte(bytes.Join([][]byte{
		[]byte(lines[0]),
		[]byte(lines[1]),
		[]byte(lines[2]),
		[]byte(lines[3]),
		[]byte(lines[4]),
		[]byte(lines[5]),
		[]byte(lines[6]),
		[]byte(lines[7]),
		[]byte(lines[8]),
		[]byte(lines[9]),
	}, []byte("\n")))

	chunks := ChunkContent(content, config)

	// Should split into multiple chunks
	if len(chunks) < 2 {
		t.Errorf("Expected at least 2 chunks for large file, got %d", len(chunks))
	}

	// Verify chunks are sequential
	for i := 1; i < len(chunks); i++ {
		if chunks[i].Index != i {
			t.Errorf("Chunk %d has wrong index: %d", i, chunks[i].Index)
		}
	}
}

func TestChunkContent_HasOverlap(t *testing.T) {
	config := ChunkConfig{
		MaxChunkSize: 30, // Small chunk for testing
		OverlapLines: 2,
	}

	// Create content that will definitely split (each line is 10 bytes + newline)
	content := []byte("1234567890\n1234567890\n1234567890\n1234567890\n1234567890\n")
	chunks := ChunkContent(content, config)

	if len(chunks) < 2 {
		t.Fatalf("Expected at least 2 chunks, got %d (content size: %d, max chunk: %d)", len(chunks), len(content), config.MaxChunkSize)
	}

	// Check that there's overlap between chunks
	// The second chunk should start before the first chunk ends
	if chunks[1].StartOffset >= chunks[0].EndOffset {
		t.Errorf("No overlap detected between chunk 0 and chunk 1")
	}
}

func TestChunkContent_CorrectOffsets(t *testing.T) {
	config := ChunkConfig{
		MaxChunkSize: 50,
		OverlapLines: 2,
	}

	content := []byte("line1\nline2\nline3\nline4\nline5\n")
	chunks := ChunkContent(content, config)

	// Last chunk should end at content length
	lastChunk := chunks[len(chunks)-1]
	if lastChunk.EndOffset != len(content) {
		t.Errorf("Last chunk EndOffset %d doesn't match content length %d", lastChunk.EndOffset, len(content))
	}

	// First chunk should start at 0
	if chunks[0].StartOffset != 0 {
		t.Errorf("First chunk StartOffset should be 0, got %d", chunks[0].StartOffset)
	}

	// Verify content matches original at offsets
	for i, chunk := range chunks {
		expectedContent := content[chunk.StartOffset:chunk.EndOffset]

		if !bytes.Equal(chunk.Content, expectedContent) {
			t.Errorf("Chunk %d content doesn't match content[%d:%d]", i, chunk.StartOffset, chunk.EndOffset)
		}
	}
}

func TestChunkContent_EmptyContent(t *testing.T) {
	config := DefaultChunkConfig()
	content := []byte("")

	chunks := ChunkContent(content, config)

	if len(chunks) != 1 {
		t.Errorf("Expected 1 chunk for empty content, got %d", len(chunks))
	}

	if len(chunks[0].Content) != 0 {
		t.Errorf("Expected empty chunk content")
	}
}

func TestChunkContent_SingleLongLine(t *testing.T) {
	config := ChunkConfig{
		MaxChunkSize: 50,
		OverlapLines: 2,
	}

	// Single line longer than MaxChunkSize (no newlines to split on)
	content := []byte("this_is_a_very_long_line_with_no_newlines_that_exceeds_the_max_chunk_size_significantly")
	chunks := ChunkContent(content, config)

	// Should still return at least one chunk with the content
	if len(chunks) == 0 {
		t.Error("Expected at least one chunk for single long line")
	}

	// The chunk should contain the content even though it exceeds MaxChunkSize
	if !bytes.Equal(chunks[0].Content, content) {
		t.Error("Single long line chunk content mismatch")
	}
}

func TestAdjustMatchOffset(t *testing.T) {
	chunk := Chunk{
		Content:     []byte("chunk content"),
		StartOffset: 1000,
		EndOffset:   1500,
		Index:       1,
	}

	match := &types.Match{
		Location: types.Location{
			Offset: types.OffsetSpan{
				Start: 10,  // Offset relative to chunk
				End:   20,
			},
		},
	}

	AdjustMatchOffset(match, chunk)

	// Offsets should be adjusted by chunk's StartOffset
	expectedStart := int64(1010)
	expectedEnd := int64(1020)

	if match.Location.Offset.Start != expectedStart {
		t.Errorf("Expected Start offset %d, got %d", expectedStart, match.Location.Offset.Start)
	}
	if match.Location.Offset.End != expectedEnd {
		t.Errorf("Expected End offset %d, got %d", expectedEnd, match.Location.Offset.End)
	}
}

func TestDefaultChunkConfig(t *testing.T) {
	config := DefaultChunkConfig()

	expectedSize := 5 * 1024 * 1024 // 5MB
	if config.MaxChunkSize != expectedSize {
		t.Errorf("Expected MaxChunkSize %d, got %d", expectedSize, config.MaxChunkSize)
	}

	if config.OverlapLines != 10 {
		t.Errorf("Expected OverlapLines 10, got %d", config.OverlapLines)
	}
}
