package matcher

import "github.com/praetorian-inc/titus/pkg/types"

// Matcher scans content for rule matches.
type Matcher interface {
	// Match scans content against all loaded rules.
	// Returns matches with offsets and capture groups.
	Match(content []byte) ([]*types.Match, error)

	// MatchWithBlobID scans content with a known BlobID.
	MatchWithBlobID(content []byte, blobID types.BlobID) ([]*types.Match, error)

	// DrainTimedOut replays any (content, blobID, rule) triples that timed out
	// during the main parallel scan, running them single-threaded with a longer
	// timeout to eliminate false drops caused by CPU-contention scheduler starvation.
	// Must be called after all parallel workers have finished (after g.Wait()).
	// Returns nil, nil when no timeouts were recorded (the common case).
	DrainTimedOut() ([]*types.Match, error)

	// Close releases resources (e.g., Hyperscan scratch space).
	Close() error
}

// Config for matcher initialization.
type Config struct {
	// Rules to compile and load into the matcher
	Rules []*types.Rule

	// MaxMatchesPerBlob limits matches returned per blob (0 = unlimited)
	MaxMatchesPerBlob int

	// ContextLines is the number of lines of context to extract before/after matches (0 = none)
	ContextLines int

	// WarnFunc, if non-nil, is called for non-fatal regex warnings
	// (timeouts, pattern errors). If nil, warnings are silently discarded.
	WarnFunc func(format string, args ...any)
}
