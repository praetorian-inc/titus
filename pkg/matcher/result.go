package matcher

import (
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// RuleStatus represents the status of a rule execution in tolerant mode
type RuleStatus int

const (
	// RuleCompleted indicates the rule finished successfully
	RuleCompleted RuleStatus = iota
	// RuleTimedOut indicates the rule exceeded its timeout
	RuleTimedOut
	// RuleError indicates the rule encountered an error
	RuleError
)

// String returns the string representation of RuleStatus
func (rs RuleStatus) String() string {
	switch rs {
	case RuleCompleted:
		return "completed"
	case RuleTimedOut:
		return "timeout"
	case RuleError:
		return "error"
	default:
		return "unknown"
	}
}

// RuleStat contains statistics about a single rule execution
type RuleStat struct {
	RuleID   string        // Rule identifier
	Status   RuleStatus    // Execution status
	Duration time.Duration // Time taken to execute
	Matches  int           // Number of matches found
	Error    error         // Error if Status is RuleError
}

// ResultSummary provides aggregate statistics for a scan
type ResultSummary struct {
	TotalRules     int // Total number of rules attempted
	CompletedRules int // Rules that completed successfully
	TimedOutRules  int // Rules that timed out
	ErrorRules     int // Rules that encountered errors
}

// MatchResult contains matches and execution statistics
type MatchResult struct {
	Matches   []*types.Match      // Successful matches
	RuleStats map[string]RuleStat // Statistics for each rule (keyed by RuleID)
	Summary   ResultSummary       // Aggregate statistics
}
