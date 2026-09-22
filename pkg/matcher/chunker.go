package matcher

import (
	"bytes"

	"github.com/praetorian-inc/titus/pkg/types"
)

const (
	defaultMaxChunkSize    = 5 * 1024 * 1024
	defaultOverlapLines    = 10
	defaultMaxOverlapBytes = 64 * 1024
)

// ChunkConfig configures file chunking behavior
type ChunkConfig struct {
	MaxChunkSize    int // Maximum size of a chunk in bytes (default: 5MB)
	OverlapLines    int // Maximum lines to overlap between chunks (default: 10)
	MaxOverlapBytes int // Maximum overlap in bytes (default: 64KB)
}

// DefaultChunkConfig returns production defaults
func DefaultChunkConfig() ChunkConfig {
	return ChunkConfig{
		MaxChunkSize:    defaultMaxChunkSize,
		OverlapLines:    defaultOverlapLines,
		MaxOverlapBytes: defaultMaxOverlapBytes,
	}
}

// Chunk represents a portion of file content with position info
type Chunk struct {
	Content     []byte // The chunk content
	StartOffset int    // Byte offset in original file where this chunk starts
	EndOffset   int    // Byte offset in original file where this chunk ends
	Index       int    // Chunk number (0-indexed)
}

// ChunkContent splits content into bounded windows with line-aware overlap.
// Oversized lines are split on the byte limit so binary content cannot
// defeat MaxChunkSize. Overlap is at most OverlapLines and MaxOverlapBytes.
func ChunkContent(content []byte, config ChunkConfig) []Chunk {
	// If content fits in a single chunk, return it
	if len(content) <= config.MaxChunkSize {
		return []Chunk{{
			Content:     content,
			StartOffset: 0,
			EndOffset:   len(content),
			Index:       0,
		}}
	}

	var chunks []Chunk
	start := 0
	for start < len(content) {
		end := start + config.MaxChunkSize
		if end > len(content) {
			end = len(content)
		} else if i := bytes.LastIndexByte(content[start:end], '\n'); i >= 0 && i+1 >= config.MaxChunkSize/2 {
			// Prefer a newline in the second half of the window so we don't stall on an early '\n'.
			end = start + i + 1
		}

		chunks = append(chunks, Chunk{
			Content:     content[start:end:end],
			StartOffset: start,
			EndOffset:   end,
			Index:       len(chunks),
		})
		if end == len(content) {
			break
		}

		next := boundBefore(content, end, config.OverlapLines, config.MaxOverlapBytes)
		if next <= start {
			next = end
		}
		start = next
	}
	return chunks
}

// AdjustMatchOffset converts chunk-relative offsets to file-absolute offsets
// and recomputes StructuralID from the absolute location.
func AdjustMatchOffset(match *types.Match, chunk Chunk, ruleStructuralID string) {
	match.Location.Offset.Start += int64(chunk.StartOffset)
	match.Location.Offset.End += int64(chunk.StartOffset)
	match.StructuralID = match.ComputeStructuralID(ruleStructuralID)
}
