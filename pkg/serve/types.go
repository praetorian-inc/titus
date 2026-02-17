package serve

import (
	"encoding/json"

	"github.com/praetorian-inc/titus/pkg/scanner"
)

// Request represents an incoming NDJSON request
type Request struct {
	Type    string          `json:"type"`    // "scan" | "scan_batch" | "validate" | "close"
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
	Type    string          `json:"type"`              // "ready" | "scan" | "scan_batch" | "validate" | "error"
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
