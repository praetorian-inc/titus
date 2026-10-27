package enum

import (
	"bytes"
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENG-9178: a location that can't be listed is flagged on its blob. A raw
// entry the history index skips (over-long path, malformed record, entry
// before any header, path token cut off by EOF) marks its destination blob
// when the blob id is readable, and only a record that cannot be tied to a
// blob leaves the index with unattributed drops.

// rawFull is raw with an explicit source mode and id, for deletions.
func rawFull(srcMode, dstMode, src, dst, status, path string) string {
	return "\n:" + srcMode + " " + dstMode + " " + src + " " + dst + " " + status + "\x00" + path + "\x00"
}

func parseStream(t *testing.T, stream string) *blobIndex {
	t.Helper()
	idx, err := parseBlobIndex(strings.NewReader(stream))
	require.NoError(t, err)
	return idx
}

func warningsOf(idx *blobIndex) string {
	var w bytes.Buffer
	idx.writeWarnings(&w)
	return w.String()
}

func TestParseBlobIndex_OverlongAddedPathMarksItsBlob(t *testing.T) {
	c := strings.Repeat("1", 40)
	long, other := strings.Repeat("a", 40), strings.Repeat("b", 40)
	idx := parseStream(t, header(c, "s")+
		raw("100644", other, "A", "ok.txt")+
		raw("100644", long, "A", strings.Repeat("p", maxRecord+1)))

	assert.True(t, idx.locationsTruncated(mustHash(t, long)), "blob whose only location was over-long is not flagged")
	assert.False(t, idx.locationsTruncated(mustHash(t, other)), "unrelated blob flagged")
	assert.False(t, idx.dropsUnattributed(), "an over-long path tied to its blob counted as unattributed")
	assert.Nil(t, idx.lookup(mustHash(t, long)))
	assert.Equal(t, "titus: skipped 1 over-long git records\n", warningsOf(idx))
}

func TestParseBlobIndex_OverlongDeletedPathMarksNothing(t *testing.T) {
	c := strings.Repeat("1", 40)
	gone := strings.Repeat("d", 40)
	idx := parseStream(t, header(c, "s")+
		rawFull("100644", "000000", gone, strings.Repeat("0", 40), "D", strings.Repeat("p", maxRecord+1)))

	assert.False(t, idx.locationsTruncated(mustHash(t, gone)), "a deletion records no location, so none was lost")
	assert.False(t, idx.marksAny())
	assert.False(t, idx.dropsUnattributed(), "a skipped deletion lost nothing, yet counted as unattributed")
	assert.Equal(t, 1, idx.stats.overlong)
}

func TestParseBlobIndex_MalformedBlobIDIsUnattributed(t *testing.T) {
	c := strings.Repeat("1", 40)
	idx := parseStream(t, header(c, "s")+
		raw("100644", "nothex"+strings.Repeat("0", 34), "A", "badhex"))

	assert.False(t, idx.marksAny(), "a record with no readable blob id marked some blob")
	assert.True(t, idx.dropsUnattributed(), "a malformed record with no blob id is not reported as an unattributed drop")
	assert.Equal(t, "titus: skipped 1 malformed git records\n", warningsOf(idx))
}

func TestParseBlobIndex_EntryBeforeHeaderMarksItsBlob(t *testing.T) {
	early, later := strings.Repeat("e", 40), strings.Repeat("f", 40)
	idx := parseStream(t, raw("100644", early, "A", "before.txt")+
		header(strings.Repeat("1", 40), "s")+
		raw("100644", later, "A", "after.txt"))

	assert.True(t, idx.locationsTruncated(mustHash(t, early)), "entry skipped for lack of a commit did not flag its blob")
	assert.False(t, idx.locationsTruncated(mustHash(t, later)))
	assert.False(t, idx.dropsUnattributed())
	assert.Equal(t, 1, idx.stats.malformed)
}

func TestParseBlobIndex_PathMissingAtEOFMarksItsBlob(t *testing.T) {
	cut := strings.Repeat("a", 40)
	stream := header(strings.Repeat("1", 40), "s") +
		"\n:000000 100644 " + strings.Repeat("0", 40) + " " + cut + " A\x00"
	idx := parseStream(t, stream)

	assert.True(t, idx.locationsTruncated(mustHash(t, cut)), "entry whose path was cut off by EOF did not flag its blob")
	assert.False(t, idx.dropsUnattributed())
	assert.Equal(t, "titus: skipped 1 malformed git records\n", warningsOf(idx))
}

func TestParseBlobIndex_OverlongSubjectIsAttributed(t *testing.T) {
	b := strings.Repeat("a", 40)
	idx := parseStream(t, header(strings.Repeat("1", 40), strings.Repeat("S", maxRecord+1))+
		raw("100644", b, "A", "ok.txt"))

	assert.Equal(t, 1, idx.stats.overlong)
	assert.False(t, idx.dropsUnattributed(), "an over-long subject carries no location, yet counted as unattributed")
	assert.False(t, idx.marksAny())
	assert.Len(t, idx.lookup(mustHash(t, b)), 1)
}

// overlongPathRepo commits a blob at a path over maxRecord on top of a base
// commit and returns the repository and the blob's content.
func overlongPathRepo(t *testing.T) (dir, longContent, baseContent string) {
	t.Helper()
	skipIfNoGit(t)
	dir = t.TempDir()
	initGitRepo(t, dir)
	baseContent = "base\n"
	writeFile(t, filepath.Join(dir, "base.txt"), baseContent)
	parent := commitAt(t, dir, "base", "2026-01-01T00:00:00Z")

	longContent = "LONG=path-over-max-record-in-a-commit\n"
	baseID, err := hex.DecodeString(hashBlob(t, dir, baseContent))
	require.NoError(t, err)
	longID, err := hex.DecodeString(hashBlob(t, dir, longContent))
	require.NoError(t, err)
	tree := hashObjectLiterally(t, dir, "tree",
		"100644 base.txt\x00"+string(baseID)+
			"100644 "+strings.Repeat("p", maxRecord+1)+"\x00"+string(longID))
	commit := gitInput(t, dir, []byte("long\n"), "commit-tree", tree, "-p", parent)
	runGit(t, dir, "update-ref", "refs/heads/long", commit)
	return dir, longContent, baseContent
}

// The go-git history index marks a blob whose commit path is over-long.
func TestGoGitHistoryIndex_OverlongPathMarksItsBlob(t *testing.T) {
	dir, longContent, baseContent := overlongPathRepo(t)
	repo, err := git.PlainOpen(dir)
	require.NoError(t, err)

	_, idx, _, err := goGitHistoryIndex(context.Background(), repo)
	require.NoError(t, err)

	assert.True(t, idx.locationsTruncated(contentHash(longContent)), "go-git: blob at an over-long path is not flagged")
	assert.False(t, idx.locationsTruncated(contentHash(baseContent)), "go-git: unrelated blob flagged")
	assert.False(t, idx.dropsUnattributed())
	assert.Equal(t, 1, idx.stats.overlong)
}

// Both walks surface the mark on the provenance a caller sees.
func TestGitHistory_OverlongCommitPathFlagsProvenance(t *testing.T) {
	dir, longContent, baseContent := overlongPathRepo(t)
	for name, walk := range enumWalks {
		t.Run(name, func(t *testing.T) {
			prov, warn := walkProv(t, dir, walk, longContent)
			assert.True(t, prov.LocationsTruncated, "blob listed with no location is not flagged (warnings %q)", warn)
			// native counts the rev-list line and the log record (2), go-git
			// its one diff entry (1); either way the skip is warned about.
			assert.Regexp(t, overlongWarning, warn)

			base, _ := walkProv(t, dir, walk, baseContent)
			assert.False(t, base.LocationsTruncated, "unrelated blob flagged")
		})
	}
}
