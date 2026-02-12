package matcher

import "time"

// Options contains configuration for matcher behavior
type Options struct {
	// Tolerant enables tolerant mode where scanning continues even if some rules timeout
	Tolerant bool

	// RuleTimeout is the maximum time allowed for a single rule to execute
	// If a rule exceeds this timeout in tolerant mode, it's marked as timed out and scanning continues
	// Default: 5 seconds (matches the regexp2 MatchTimeout)
	RuleTimeout time.Duration
}

// DefaultOptions returns the default options for the matcher
func DefaultOptions() Options {
	return Options{
		Tolerant:    false,
		RuleTimeout: 5 * time.Second,
	}
}
