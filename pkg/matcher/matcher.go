package matcher

import "github.com/praetorian-inc/titus/pkg/types"

// Matcher scans content for rule matches.
type Matcher interface {
	// Match scans content against all loaded rules.
	// Returns matches with offsets and capture groups.
	Match(content []byte) ([]*types.Match, error)

	// MatchWithBlobID scans content with a known BlobID.
	MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error)

	// Close releases resources (e.g., Hyperscan scratch space).
	Close() error
}

// Config for matcher initialization.
type Config struct {
	// Rules to compile and load into the matcher
	Rules []*types.Rule

	// MaxMatchesPerBlob limits matches returned per blob (0 = unlimited)
	MaxMatchesPerBlob int
}

// New creates a new Matcher with the given config.
// Currently returns a Hyperscan-based implementation.
func New(cfg Config) (Matcher, error) {
	return NewHyperscan(cfg.Rules)
}
