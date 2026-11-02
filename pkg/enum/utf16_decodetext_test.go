package enum

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

// ENG-9178: decodeText reports whether it transcoded content. UTF-16 with a
// BOM (either byte order) is transcoded to its UTF-8 text; UTF-8 is passed
// through untouched.
func TestDecodeText_ReportsTranscoding(t *testing.T) {
	text := fakeTokenLine('d')
	for _, tc := range []struct {
		name           string
		content        []byte
		wantText       string
		wantTranscoded bool
	}{
		{"UTF-16LE with BOM", encodeUTF16(t, text, false, true), text, true},
		{"UTF-16BE with BOM", encodeUTF16(t, text, true, true), text, true},
		{"UTF-8", []byte(text), text, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, isText, transcoded := decodeText(tc.content)
			assert.True(t, isText)
			assert.Equal(t, tc.wantTranscoded, transcoded)
			assert.Equal(t, tc.wantText, string(got))
		})
	}
}

// ENG-9178: textBlobID names a git blob by the BlobID of the text the
// matcher sees. In a SHA-1 repository that is the git object id for UTF-8
// content and the hash of the decoded text for transcoded UTF-16, so both
// agree with the filesystem enumerator's BlobID for the same file. In a
// SHA-256 repository the text is always hashed.
func TestTextBlobID_FollowsDecodeText(t *testing.T) {
	text := fakeTokenLine('e')
	for _, tc := range []struct {
		name    string
		raw     []byte
		sha256  bool
		gitID   types.BlobID
		wantDup bool // want == gitID
	}{
		{name: "UTF-8, SHA-1 repo keeps the object id", raw: []byte(text), gitID: types.ComputeBlobID([]byte(text)), wantDup: true},
		{name: "UTF-16, SHA-1 repo hashes the decoded text", raw: encodeUTF16(t, text, false, true)},
		{name: "UTF-8, SHA-256 repo hashes the text", raw: []byte(text), sha256: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gitID := tc.gitID
			if gitID == (types.BlobID{}) {
				// A SHA-256 object id or a raw UTF-16 object id: never the
				// BlobID of the decoded text.
				gitID = types.ComputeBlobID(tc.raw)
				if tc.sha256 {
					gitID = blobIDFrom(0xAB)
				}
			}
			decoded, _, transcoded := decodeText(tc.raw)
			got := textBlobID(gitID, decoded, transcoded, tc.sha256)
			assert.Equal(t, types.ComputeBlobID([]byte(text)), got, "BlobID of the decoded text")
			assert.Equal(t, tc.wantDup, got == gitID)
		})
	}
}
