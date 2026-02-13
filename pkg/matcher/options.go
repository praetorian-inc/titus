package matcher

import (
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Options configures matching behavior
type Options struct {
	Tolerant bool          // Continue on errors instead of failing fast
	Timeout  time.Duration // Per-rule timeout (0 = no timeout)
}

// DefaultOptions returns the default matching options
func DefaultOptions() Options {
	return Options{
		Tolerant: false,
		Timeout:  0,
	}
}

// RuleStatus represents the completion status of a rule
type RuleStatus int

const (
	RuleCompleted RuleStatus = iota // Rule completed successfully
	RuleTimedOut                     // Rule timed out
	RuleError                        // Rule encountered an error
)

// RuleStat contains statistics about a single rule's execution
type RuleStat struct {
	RuleID   string        // Rule identifier
	Status   RuleStatus    // Completion status
	Matches  int           // Number of matches found
	Duration time.Duration // Time spent matching this rule
	Error    error         // Error if Status == RuleError
}

// ResultSummary provides aggregate statistics across all rules
type ResultSummary struct {
	TotalRules     int // Total number of rules processed
	CompletedRules int // Number of rules that completed successfully
	TimedOutRules  int // Number of rules that timed out
	ErrorRules     int // Number of rules that encountered errors
}

// MatchResult contains matches and execution statistics
type MatchResult struct {
	Matches   []*types.Match      // All matches found
	RuleStats map[string]RuleStat // Per-rule statistics
	Summary   ResultSummary       // Aggregate statistics
}
