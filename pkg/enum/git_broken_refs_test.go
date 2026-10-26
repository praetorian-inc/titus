package enum

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

const (
	indexUnavailableWarning = "history index unavailable"
	missingObjectsWarning   = "git objects are missing"
)

// blobProv is the comparable provenance of one scanned blob.
type blobProv struct {
	Paths     string
	Commits   string
	Truncated bool
}

// walkAllProv runs one walk and returns every scanned blob's provenance by
// content, and the warnings.
func walkAllProv(t *testing.T, dir string, walk func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error) (map[string]blobProv, string) {
	t.Helper()
	e := nativeEnum(dir)
	var warn bytes.Buffer
	e.warn = &warn
	out := map[string]blobProv{}
	err := walk(e)(context.Background(), func(c []byte, _ types.BlobID, p types.Provenance) error {
		g := p.(types.GitProvenance)
		var commits []string
		for _, l := range g.Locations {
			if l.Commit != nil {
				commits = append(commits, l.Commit.CommitID)
			} else {
				commits = append(commits, "-")
			}
		}
		paths := locPaths(g.Locations)
		sort.Strings(paths)
		out[string(c)] = blobProv{Paths: strings.Join(paths, ","), Commits: strings.Join(commits, ","), Truncated: g.LocationsTruncated}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v (warnings %q)", err, warn.String())
	}
	return out, warn.String()
}
