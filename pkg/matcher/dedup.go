package matcher

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/praetorian-inc/titus/pkg/types"
)

// DedupeMode controls how matches are deduplicated.
type DedupeMode int

const (
	// DedupeByLocation deduplicates by exact location (rule + blob + offset).
	// Same secret at different locations counts as separate findings.
	DedupeByLocation DedupeMode = iota

	// DedupeByContent deduplicates by matched content (rule + secret value).
	// Same secret appearing multiple times counts as one finding.
	// This matches NoseyParker's behavior.
	DedupeByContent
)

// Deduplicator removes duplicate matches based on configurable criteria.
type Deduplicator struct {
	seen map[string]bool
	mode DedupeMode
}

// NewDeduplicator creates a new deduplicator with location-based deduplication.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]bool),
		mode: DedupeByLocation,
	}
}

// NewContentDeduplicator creates a deduplicator that deduplicates by content.
// This matches NoseyParker's behavior - same secret value counts once.
func NewContentDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]bool),
		mode: DedupeByContent,
	}
}

// SetMode changes the deduplication mode.
func (d *Deduplicator) SetMode(mode DedupeMode) {
	d.mode = mode
}

// IsDuplicate returns true if match was already seen.
func (d *Deduplicator) IsDuplicate(m *types.Match) bool {
	key := d.computeKey(m)
	return d.seen[key]
}

// Add marks a match as seen.
func (d *Deduplicator) Add(m *types.Match) {
	key := d.computeKey(m)
	d.seen[key] = true
}

// Reset clears the deduplicator for reuse.
func (d *Deduplicator) Reset() {
	clear(d.seen)
}

// computeKey generates the deduplication key based on mode.
func (d *Deduplicator) computeKey(m *types.Match) string {
	switch d.mode {
	case DedupeByContent:
		// Dedupe by rule + captured secret value (like NoseyParker)
		// Use capture groups which contain the actual secret, not Snippet.Matching
		// which includes surrounding context
		h := sha256.New()
		h.Write([]byte(m.RuleID))
		h.Write([]byte{0})
		// Use all capture groups to form the content key
		for _, group := range m.Groups {
			h.Write(group)
			h.Write([]byte{0})
		}
		return hex.EncodeToString(h.Sum(nil))
	default:
		// Dedupe by structural ID (location-based)
		return m.StructuralID
	}
}
