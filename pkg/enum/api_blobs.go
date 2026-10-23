package enum

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"os"
	"slices"

	"github.com/praetorian-inc/titus/pkg/repoid"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Shared helpers for the hosting-API enumerators (GitHub, GitLab).

// apiRepoIdentity returns the repository value for an API enumerator: the
// configured base URL's host (or defaultHost) joined with fullPath. A path
// repoid rejects falls back to the display-safe name with no host.
func apiRepoIdentity(baseURL, defaultHost, fullPath string) string {
	if id := repoid.FromBaseURL(baseURL, defaultHost, fullPath); id != "" {
		return id
	}
	return typedRepoIdentity(fullPath)
}

// blobKey identifies one blob of a tree listing. An entry with no SHA is
// keyed by its path, in a separate field, so it never merges with a
// SHA-keyed entry (even one whose SHA equals the path) or with another
// SHA-less entry (paths are unique within a tree).
type blobKey struct{ sha, path string }

// blobPaths groups the paths of an API tree listing by blob, in first-seen
// order.
type blobPaths struct {
	order []blobKey
	paths map[blobKey][]string
}

func (b *blobPaths) add(sha, path string) {
	k := blobKey{sha: sha}
	if sha == "" {
		k.path = path
	}
	if b.paths == nil {
		b.paths = make(map[blobKey][]string)
	}
	if _, seen := b.paths[k]; !seen {
		b.order = append(b.order, k)
	}
	b.paths[k] = append(b.paths[k], path)
}

// all yields the path list of each blob.
func (b *blobPaths) all() iter.Seq[[]string] {
	return func(yield func([]string) bool) {
		for _, k := range b.order {
			if !yield(b.paths[k]) {
				return
			}
		}
	}
}

// apiProvenance is the provenance of one blob found through a hosting API:
// every path (sorted), no commit, and no local root.
func apiProvenance(id string, paths []string) types.GitProvenance {
	slices.Sort(paths)
	locs := make([]types.GitLocation, len(paths))
	for i, p := range paths {
		locs[i] = types.GitLocation{Path: p}
	}
	return types.GitProvenance{RepoPath: id, BlobPath: paths[0], RemoteIdentity: true, Locations: locs}
}

// overSizeLimit reports whether n bytes exceed the configured limit
// (0 = no limit).
func overSizeLimit(n int, limit int64) bool {
	return limit > 0 && int64(n) > limit
}

// httpFailure describes a failed API request by status only. API client
// error text embeds the request URL, which can carry base-URL credentials,
// so it is never printed.
func httpFailure(resp *http.Response) string {
	if resp != nil && resp.StatusCode != 0 {
		return fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return "request failed"
}

// apiError is the error for a failed hosting-API call: op and the HTTP
// status only, for the same reason as httpFailure. A done ctx is wrapped so
// errors.Is(err, context.Canceled) holds.
func apiError(ctx context.Context, op string, resp *http.Response) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return fmt.Errorf("%s: %s", op, httpFailure(resp))
}

// errOverSizeLimit stops a download that would exceed the size limit.
var errOverSizeLimit = errors.New("exceeds size limit")

// cappedBuffer collects a response body up to limit bytes (0 = no limit)
// and fails with errOverSizeLimit past it. stop must abort the request.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int64
	stop  func()
}

// ReadFrom is what io.Copy calls with the response body: it reads at most
// limit+1 bytes and, past the limit, closes the body. A closed body makes
// any later drain of it (the GitLab client drains in a defer) fail at once;
// cancelling the request alone closes the connection asynchronously, so a
// drain could still read what is in flight.
func (c *cappedBuffer) ReadFrom(r io.Reader) (int64, error) {
	if c.limit <= 0 {
		return c.buf.ReadFrom(r)
	}
	n, err := c.buf.ReadFrom(io.LimitReader(r, c.limit+1))
	if err != nil {
		return n, err
	}
	if overSizeLimit(c.buf.Len(), c.limit) {
		if cl, ok := r.(io.Closer); ok {
			cl.Close()
		}
		c.stop()
		return n, errOverSizeLimit
	}
	return n, nil
}

// Write is used when io.Copy does not call ReadFrom (a source with WriteTo).
func (c *cappedBuffer) Write(p []byte) (int, error) {
	if overSizeLimit(c.buf.Len()+len(p), c.limit) {
		c.stop()
		return 0, errOverSizeLimit
	}
	return c.buf.Write(p)
}

// warnBlobSkipped reports a blob none of whose paths could be read. Only the
// repository identity, the first path (control characters escaped) and the
// reason are printed.
func warnBlobSkipped(w io.Writer, id string, paths []string, reason string) {
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintf(w, "warning: skipping %s: %s: %s\n", id, types.SanitizeDisplay(paths[0]), reason)
}
