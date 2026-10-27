package enum

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// crlf turns every LF in s into CRLF, as git's eol=crlf checkout does.
func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

// checkoutConversionCase is one repository whose file.path git rewrote at
// checkout, and whether the working-tree copy really differs from HEAD.
type checkoutConversionCase struct {
	name   string
	format string // "sha1" or "sha256"
	attrs  string // .gitattributes
	file   string
	// write returns the bytes written before git add.
	write func(t *testing.T, text string) []byte
	// modify, when set, appends uncommitted text to the restored file, so the
	// working tree really differs from HEAD.
	modify string
}

func (tc checkoutConversionCase) init(t *testing.T, dir string) {
	t.Helper()
	if tc.format == "sha1" {
		initGitRepo(t, dir)
		return
	}
	initGitRepoFormat(t, dir, tc.format)
}

// ENG-9178: a tracked file git converted at checkout (eol=crlf, or
// working-tree-encoding=UTF-16LE-BOM) is the HEAD blob. After deleting it
// and restoring it with `git checkout --`, the scan --git shape reports it
// once, at its commit location, with no working-tree location. A working-tree
// file that really differs from HEAD still gets its working-tree location.
func TestCombinedEnumerator_CheckoutConversionsAreHeldByHead(t *testing.T) {
	plain := func(_ *testing.T, text string) []byte { return []byte(text) }
	utf16le := func(t *testing.T, text string) []byte { return encodeUTF16(t, text, false, true) }

	for _, tc := range []checkoutConversionCase{
		{name: "a. sha1 eol=crlf", format: "sha1", attrs: "* text eol=crlf\n", file: "c.yml", write: plain},
		{name: "b. sha256 eol=crlf", format: "sha256", attrs: "* text eol=crlf\n", file: "c.yml", write: plain},
		{name: "c. sha256 UTF-16LE-BOM", format: "sha256", attrs: "*.ps1 working-tree-encoding=UTF-16LE-BOM\n", file: "c.ps1", write: utf16le},
		{name: "d. sha1 eol=crlf, file modified", format: "sha1", attrs: "* text eol=crlf\n", file: "c.yml", write: plain, modify: fakeTokenLine('e')},
	} {
		t.Run(tc.name, func(t *testing.T) {
			skipIfNoGit(t)
			dir := t.TempDir()
			tc.init(t, dir)
			text := fakeTokenLine('d')
			writeFile(t, filepath.Join(dir, ".gitattributes"), tc.attrs)
			require.NoError(t, os.WriteFile(filepath.Join(dir, tc.file), tc.write(t, text), 0o644))
			a := commitAt(t, dir, "A", "2026-01-01T00:00:00Z")

			// git stored the converted text: the blob is the UTF-8, LF text.
			blob := gitOutput(t, dir, "cat-file", "-p", "HEAD:"+tc.file)
			require.Equal(t, strings.TrimSuffix(text, "\n"), blob, "committed blob")

			require.NoError(t, os.Remove(filepath.Join(dir, tc.file)))
			runGit(t, dir, "checkout", "--", tc.file)
			restored, err := os.ReadFile(filepath.Join(dir, tc.file))
			require.NoError(t, err)
			require.NotEqual(t, text, string(restored), "git must have converted the file at checkout")

			if tc.modify != "" {
				f, err := os.OpenFile(filepath.Join(dir, tc.file), os.O_APPEND|os.O_WRONLY, 0)
				require.NoError(t, err)
				_, err = f.WriteString(crlf(tc.modify))
				require.NoError(t, err)
				require.NoError(t, f.Close())
			}

			got := newAllLocs()
			require.NoError(t, gitAndWorktree(dir, Config{}).Enumerate(context.Background(), got.callback))

			// Every location any callback reported for the file.
			var locs []wtLoc
			for id := range got.locs {
				for _, l := range got.of(id) {
					if l.path == tc.file {
						locs = append(locs, l)
					}
				}
			}
			slices.SortFunc(locs, func(x, y wtLoc) int { return strings.Compare(x.commit, y.commit) })

			want := []wtLoc{{tc.file, "", true}, {tc.file, a, false}}
			if tc.modify == "" {
				want = []wtLoc{{tc.file, a, false}}
			}
			assert.Equal(t, want, locs, "locations of %s across all callbacks", tc.file)
			assert.Equal(t, []wtLoc{{tc.file, a, false}}, got.of(types.ComputeBlobID([]byte(text))),
				"locations of the committed blob")
		})
	}
}
