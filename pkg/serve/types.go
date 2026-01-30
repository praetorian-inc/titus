package serve

import (
	"encoding/json"

	"github.com/praetorian-inc/titus/pkg/scanner"
)

// Request represents an incoming NDJSON request
type Request struct {
	Type    string          `json:"type"`    // "scan" | "scan_batch" | "close"
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
	Type    string          `json:"type"`              // "ready" | "scan" | "scan_batch" | "error"
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// ReadyData is the data field for "ready" responses
type ReadyData struct {
	Version string `json:"version"`
}
