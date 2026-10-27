package enum

import (
	"bytes"
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// enumWalks are the two history walks, keyed by name, for tests that
// assert the same behavior on both.
var enumWalks = map[string]func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error{
	"native": func(e *GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error {
		return e.enumerateAllHistoryNative
	},
	"go-git": func(e *GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error {
		return e.enumerateAllHistory
	},
}

// runWalkWarn runs one walk over dir and returns the scanned contents and
// the warnings.
func runWalkWarn(t *testing.T, dir string, walk func(*GitEnumerator) func(context.Context, func([]byte, types.BlobID, types.Provenance) error) error) (map[string]bool, string) {
	t.Helper()
	e := nativeEnum(dir)
	var warn bytes.Buffer
	e.warn = &warn
	seen := map[string]bool{}
	err := walk(e)(context.Background(), func(content []byte, _ types.BlobID, _ types.Provenance) error {
		seen[string(content)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v (warnings %q)", err, warn.String())
	}
	return seen, warn.String()
}
