package matcher

import (
	"bytes"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChunkContent_SmallContentIsSingleChunk(t *testing.T) {
	content := []byte("short")
	chunks := ChunkContent(content, ChunkConfig{MaxChunkSize: 100, OverlapLines: 10, MaxOverlapBytes: 20})
	require.Len(t, chunks, 1)
	assert.Equal(t, content, chunks[0].Content)
	assert.Equal(t, 0, chunks[0].StartOffset)
	assert.Equal(t, len(content), chunks[0].EndOffset)
}

func TestChunkContent_TinyMaxChunkSizeStillAdvances(t *testing.T) {
	content := []byte("abcdef")
	chunks := ChunkContent(content, ChunkConfig{MaxChunkSize: 1, OverlapLines: 10, MaxOverlapBytes: 1})
	require.Len(t, chunks, len(content))
	for i, chunk := range chunks {
		assert.Equal(t, 1, len(chunk.Content))
		assert.Equal(t, i, chunk.StartOffset)
	}
}

func TestChunkContent_OversizedLineIsByteBounded(t *testing.T) {
	config := ChunkConfig{MaxChunkSize: 100, OverlapLines: 10, MaxOverlapBytes: 20}
	content := bytes.Repeat([]byte{0x00}, 250)
	chunks := ChunkContent(content, config)
	require.Greater(t, len(chunks), 1)

	for _, chunk := range chunks {
		assert.LessOrEqual(t, len(chunk.Content), config.MaxChunkSize)
		assert.Equal(t, chunk.EndOffset-chunk.StartOffset, len(chunk.Content))
	}
	for i := 1; i < len(chunks); i++ {
		overlap := chunks[i-1].EndOffset - chunks[i].StartOffset
		assert.Greater(t, overlap, 0)
		assert.LessOrEqual(t, overlap, config.MaxOverlapBytes)
		assert.Greater(t, chunks[i].StartOffset, chunks[i-1].StartOffset)
	}
	assert.Equal(t, 0, chunks[0].StartOffset)
	assert.Equal(t, len(content), chunks[len(chunks)-1].EndOffset)
}

func TestChunkContent_GoSourceSplitsOnLines(t *testing.T) {
	var content []byte
	for range 40 {
		content = append(content, []byte("func helper() { return nil } // line padding\n")...)
	}
	config := ChunkConfig{MaxChunkSize: 200, OverlapLines: 2, MaxOverlapBytes: 500}
	chunks := ChunkContent(content, config)
	require.Greater(t, len(chunks), 1)

	for i, chunk := range chunks {
		if i < len(chunks)-1 {
			assert.True(t, bytes.HasSuffix(chunk.Content, []byte("\n")))
		}
		if chunk.StartOffset > 0 {
			assert.Equal(t, byte('\n'), content[chunk.StartOffset-1])
		}
	}
	for i := 1; i < len(chunks); i++ {
		overlap := content[chunks[i].StartOffset:chunks[i-1].EndOffset]
		assert.Equal(t, 2, bytes.Count(overlap, []byte("\n")))
	}
}

func TestChunkContent_PrefersNewlineNearChunkEnd(t *testing.T) {
	config := ChunkConfig{MaxChunkSize: 20, OverlapLines: 1, MaxOverlapBytes: 5}
	content := []byte("aaaaaaaaaa\nbbbbbbbbbb\ncccccccccc")
	chunks := ChunkContent(content, config)
	require.Greater(t, len(chunks), 1)
	assert.True(t, bytes.HasSuffix(chunks[0].Content, []byte("\n")))
}

func TestAdjustMatchOffset_RecomputesStructuralID(t *testing.T) {
	match := &types.Match{
		BlobID: types.ComputeBlobID([]byte("blob")),
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 10, End: 20},
		},
	}
	ruleSID := "rule-sid"
	match.StructuralID = match.ComputeStructuralID(ruleSID)
	stale := match.StructuralID

	AdjustMatchOffset(match, Chunk{StartOffset: 100}, ruleSID)

	assert.Equal(t, int64(110), match.Location.Offset.Start)
	assert.Equal(t, int64(120), match.Location.Offset.End)
	assert.Equal(t, match.ComputeStructuralID(ruleSID), match.StructuralID)
	assert.NotEqual(t, stale, match.StructuralID)
}
