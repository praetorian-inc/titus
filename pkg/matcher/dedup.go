package matcher

import "github.com/praetorian-inc/titus/pkg/types"

// Deduplicator removes duplicate matches based on structural ID.
type Deduplicator struct {
	seen map[string]bool
}

// NewDeduplicator creates a new deduplicator.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]bool),
	}
}

// IsDuplicate returns true if match was already seen.
func (d *Deduplicator) IsDuplicate(m *types.Match) bool {
	return d.seen[m.StructuralID]
}

// Add marks a match as seen.
func (d *Deduplicator) Add(m *types.Match) {
	d.seen[m.StructuralID] = true
}

// Reset clears the deduplicator for reuse.
func (d *Deduplicator) Reset() {
	clear(d.seen)
}
