package scanner

import "github.com/praetorian-inc/titus/pkg/types"

// ContentItem represents a content item to scan
type ContentItem struct {
	Source   string            `json:"source"`   // e.g., "script:inline:1", "script:external:url"
	Content  string            `json:"content"`  // the actual content to scan
	Metadata map[string]string `json:"metadata"` // optional metadata
}

// ScanResult represents scan results for a single item
type ScanResult struct {
	Source  string         `json:"source"`
	Matches []*types.Match `json:"matches"`
}

// BatchScanResult represents batch scan results
type BatchScanResult struct {
	Results []ScanResult `json:"results"`
	Total   int          `json:"total"`
}

// DebugLogger provides platform-specific logging
type DebugLogger interface {
	Log(format string, args ...interface{})
}

// NoopLogger is a no-op logger
type NoopLogger struct{}

func (NoopLogger) Log(format string, args ...interface{}) {}
