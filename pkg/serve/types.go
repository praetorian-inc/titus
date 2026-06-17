package serve

import (
	"encoding/json"

	"github.com/praetorian-inc/titus/pkg/scanner"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Request represents an incoming NDJSON request
type Request struct {
	Type    string          `json:"type"` // "scan" | "scan_batch" | "validate" | "close"
	Payload json.RawMessage `json:"payload"`
}

// ScanPayload is the payload for "scan" requests
type ScanPayload struct {
	Content string `json:"content"`
	Source  string `json:"source"`
}

// ScanBatchPayload is the payload for "scan_batch" requests
type ScanBatchPayload struct {
	Items []scanner.ContentItem `json:"items"`
}

// Response represents an outgoing NDJSON response
type Response struct {
	Success bool            `json:"success"`
	Type    string          `json:"type"` // "ready" | "scan" | "scan_batch" | "validate" | "error"
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// ReadyData is the data field for "ready" responses
type ReadyData struct {
	Version string `json:"version"`
}

// ValidatePayload is the payload for "validate" requests
type ValidatePayload struct {
	RuleID      string            `json:"rule_id"`
	Secret      string            `json:"secret"`
	NamedGroups map[string]string `json:"named_groups"`
}

// ValidateResult is the result for "validate" responses
type ValidateResult struct {
	Status     string            `json:"status"`
	Confidence float64           `json:"confidence"`
	Message    string            `json:"message"`
	Details    map[string]string `json:"details,omitempty"`
}

// ScanPathPayload is the payload for "scan_path" requests
type ScanPathPayload struct {
	Path            string `json:"path"`
	MaxFileSize     int64  `json:"max_file_size,omitempty"`
	ExtractArchives string `json:"extract_archives,omitempty"`
	IgnoreFile      string `json:"ignore_file,omitempty"`
}

// ScanGitPayload is the payload for "scan_git" requests
type ScanGitPayload struct {
	Path        string `json:"path"`
	WalkAll     bool   `json:"walk_all,omitempty"`
	MaxFileSize int64  `json:"max_file_size,omitempty"`
}

// ScanBlobResult is a streaming result for a single blob with matches
type ScanBlobResult struct {
	Source  string         `json:"source"`
	Kind    string         `json:"kind"`
	Matches []*types.Match `json:"matches"`
}

// ScanDoneData is the final message after a scan_path or scan_git completes
type ScanDoneData struct {
	TotalMatches int `json:"total_matches"`
	TotalBlobs   int `json:"total_blobs"`
}
