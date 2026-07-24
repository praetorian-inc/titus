package matcher

import (
	"time"

	"github.com/dlclark/regexp2"
	"github.com/praetorian-inc/titus/pkg/types"
)

func init() {
	// regexp2's internal "fast clock" only ticks every 100ms by default,
	// making any MatchTimeout shorter than ~200ms effectively meaningless.
	// Must be called before any regexp2.Compile with MatchTimeout set.
	regexp2.SetTimeoutCheckPeriod(10 * time.Millisecond)
}

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

	// MatchTimeout is the per-match timeout for regexp2 pattern execution.
	// If zero, the default of 500ms is used. The retry pass uses a longer
	// timeout derived from this value (10x, capped at 30s).
	MatchTimeout time.Duration
}
