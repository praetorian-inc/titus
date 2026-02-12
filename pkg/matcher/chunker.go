package matcher

import (
	"bytes"

	"github.com/praetorian-inc/titus/pkg/types"
)

// ChunkConfig configures file chunking behavior
type ChunkConfig struct {
	MaxChunkSize int // Maximum size of a chunk in bytes (default: 5MB)
	OverlapLines int // Number of lines to overlap between chunks (default: 10)
}

// DefaultChunkConfig returns production defaults
func DefaultChunkConfig() ChunkConfig {
	return ChunkConfig{
		MaxChunkSize: 5 * 1024 * 1024, // 5MB
		OverlapLines: 10,
	}
}

// Chunk represents a portion of file content with position info
type Chunk struct {
	Content     []byte // The chunk content
	StartOffset int    // Byte offset in original file where this chunk starts
	EndOffset   int    // Byte offset in original file where this chunk ends
	Index       int    // Chunk number (0-indexed)
}

// ChunkContent splits content at line boundaries with overlap
// If content is smaller than MaxChunkSize, returns a single chunk
// Otherwise splits at newlines, ensuring chunks don't exceed MaxChunkSize
// and overlap by OverlapLines between consecutive chunks
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
	lines := bytes.Split(content, []byte("\n"))

	// Edge case: empty content returns empty line slice
	if len(lines) == 0 {
		return []Chunk{{
			Content:     content,
			StartOffset: 0,
			EndOffset:   len(content),
			Index:       0,
		}}
	}

	var currentChunk []byte
	var chunkStartOffset int
	var overlapStartLine int

	for lineIdx := 0; lineIdx < len(lines); lineIdx++ {
		line := lines[lineIdx]

		// Add newline back (except for last line)
		lineWithNewline := line
		if lineIdx < len(lines)-1 {
			lineWithNewline = append(line, '\n')
		}

		// Check if adding this line would exceed chunk size
		if len(currentChunk)+len(lineWithNewline) > config.MaxChunkSize && len(currentChunk) > 0 {
			// Save current chunk (keep newlines intact for pattern matching)
			chunks = append(chunks, Chunk{
				Content:     currentChunk,
				StartOffset: chunkStartOffset,
				EndOffset:   chunkStartOffset + len(currentChunk),
				Index:       len(chunks),
			})

			// Calculate overlap starting point
			overlapStartLine = maxInt(0, lineIdx-config.OverlapLines)

			// Find byte offset for overlap start
			chunkStartOffset = 0
			for i := 0; i < overlapStartLine; i++ {
				chunkStartOffset += len(lines[i]) + 1 // +1 for newline
			}

			// Rebuild chunk from overlap point to current line
			currentChunk = nil
			for i := overlapStartLine; i < lineIdx; i++ {
				currentChunk = append(currentChunk, lines[i]...)
				if i < len(lines)-1 {
					currentChunk = append(currentChunk, '\n')
				}
			}
		}

		// Add current line to chunk
		currentChunk = append(currentChunk, lineWithNewline...)
	}

	// Don't forget the last chunk (keep newlines intact)
	if len(currentChunk) > 0 {
		chunks = append(chunks, Chunk{
			Content:     currentChunk,
			StartOffset: chunkStartOffset,
			EndOffset:   len(content),
			Index:       len(chunks),
		})
	}

	// If no chunks were created (shouldn't happen), return original as single chunk
	if len(chunks) == 0 {
		return []Chunk{{
			Content:     content,
			StartOffset: 0,
			EndOffset:   len(content),
			Index:       0,
		}}
	}

	return chunks
}

// AdjustMatchOffset converts chunk-relative offsets to file-absolute offsets
func AdjustMatchOffset(match *types.Match, chunk Chunk) {
	match.Location.Offset.Start += int64(chunk.StartOffset)
	match.Location.Offset.End += int64(chunk.StartOffset)
}

// maxInt returns the maximum of two integers
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
