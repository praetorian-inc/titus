package enum

import (
	"context"
	"sync"

	"github.com/praetorian-inc/titus/pkg/types"
)

// CombinedEnumerator runs multiple enumerators sequentially and deduplicates
// blobs by BlobID so each unique blob is yielded at most once.
type CombinedEnumerator struct {
	enumerators []Enumerator
}

// NewCombinedEnumerator creates a CombinedEnumerator that wraps the provided
// enumerators. They are run in order and duplicate blobs (same BlobID) are
// suppressed.
func NewCombinedEnumerator(enumerators ...Enumerator) *CombinedEnumerator {
	return &CombinedEnumerator{enumerators: enumerators}
}

// Enumerate runs each child enumerator in sequence, passing unique blobs to
// callback. A blob is considered a duplicate if its BlobID was already seen
// by a previous call across any enumerator in this combined set.
func (c *CombinedEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	var mu sync.Mutex
	seen := make(map[types.BlobID]bool)

	for _, e := range c.enumerators {
		err := e.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			mu.Lock()
			if seen[blobID] {
				mu.Unlock()
				return nil
			}
			seen[blobID] = true
			mu.Unlock()

			return callback(content, blobID, prov)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
