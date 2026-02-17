package serve

import (
	"bufio"
	"context"
	"encoding/json"
	"io"

	"github.com/praetorian-inc/titus/pkg/scanner"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
)

// Version is the server protocol version
const Version = "1.0.0"

// Server manages the streaming scanner
type Server struct {
	core      *scanner.Core
	validator *validator.Engine
	encoder   *json.Encoder
	decoder   *json.Decoder
}

// NewServer creates a new streaming server
func NewServer(core *scanner.Core, in io.Reader, out io.Writer) *Server {
	return &Server{
		core:    core,
		encoder: json.NewEncoder(out),
		decoder: json.NewDecoder(bufio.NewReader(in)),
	}
}

// SetValidator sets the validator engine
func (s *Server) SetValidator(v *validator.Engine) {
	s.validator = v
}

// Run starts the server main loop
func (s *Server) Run(ctx context.Context) error {
	// Send ready signal
	s.sendReady()

	// Use buffered channels for incoming requests
	reqChan := make(chan Request, 1)
	errChan := make(chan error, 1)

	go func() {
		for {
			var req Request
			if err := s.decoder.Decode(&req); err != nil {
				errChan <- err
				return
			}
			select {
			case reqChan <- req:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Process requests until stdin closes or context cancels
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errChan:
			// Drain any pending requests before handling EOF
			for {
				select {
				case req := <-reqChan:
					if s.processRequest(ctx, req) {
						return nil
					}
				default:
					// No more pending requests
					if err == io.EOF {
						return nil
					}
					s.sendError("decode", err.Error())
					return nil
				}
			}
		case req := <-reqChan:
			if s.processRequest(ctx, req) {
				return nil
			}
		}
	}
}

// processRequest handles a single request and returns true if the server should exit
func (s *Server) processRequest(ctx context.Context, req Request) bool {
	switch req.Type {
	case "scan":
		s.handleScan(req.Payload)
	case "scan_batch":
		s.handleScanBatch(req.Payload)
	case "validate":
		s.handleValidate(ctx, req.Payload)
	case "close":
		return true
	default:
		s.sendError("unknown", "unknown request type: "+req.Type)
	}
	return false
}

func (s *Server) sendReady() {
	data, _ := json.Marshal(ReadyData{Version: Version})
	s.encoder.Encode(Response{
		Success: true,
		Type:    "ready",
		Data:    data,
	})
}

func (s *Server) handleScan(payload json.RawMessage) {
	var p ScanPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		s.sendError("scan", err.Error())
		return
	}

	result, err := s.core.Scan(p.Content, p.Source)
	if err != nil {
		s.sendError("scan", err.Error())
		return
	}

	data, _ := json.Marshal(result)
	s.encoder.Encode(Response{
		Success: true,
		Type:    "scan",
		Data:    data,
	})
}

func (s *Server) handleScanBatch(payload json.RawMessage) {
	var p ScanBatchPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		s.sendError("scan_batch", err.Error())
		return
	}

	result, err := s.core.ScanBatch(p.Items)
	if err != nil {
		s.sendError("scan_batch", err.Error())
		return
	}

	data, _ := json.Marshal(result)
	s.encoder.Encode(Response{
		Success: true,
		Type:    "scan_batch",
		Data:    data,
	})
}

func (s *Server) handleValidate(ctx context.Context, payload json.RawMessage) {
	var p ValidatePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		s.sendError("validate", err.Error())
		return
	}

	// Check if validator is available
	if s.validator == nil {
		s.sendError("validate", "validator not configured")
		return
	}

	// Create a types.Match from the payload
	match := &types.Match{
		RuleID:      p.RuleID,
		NamedGroups: make(map[string][]byte),
	}

	// Convert string named groups to byte slices
	for key, value := range p.NamedGroups {
		match.NamedGroups[key] = []byte(value)
	}

	// Add the secret to named groups if not already present
	if _, exists := match.NamedGroups["secret"]; !exists {
		match.NamedGroups["secret"] = []byte(p.Secret)
	}

	// Validate the match
	validationResult, err := s.validator.ValidateMatch(ctx, match)
	if err != nil {
		s.sendError("validate", err.Error())
		return
	}

	// Convert ValidationResult to ValidateResult
	result := ValidateResult{
		Status:     string(validationResult.Status),
		Confidence: validationResult.Confidence,
		Message:    validationResult.Message,
		Details:    validationResult.Details,
	}

	data, _ := json.Marshal(result)
	s.encoder.Encode(Response{
		Success: true,
		Type:    "validate",
		Data:    data,
	})
}

func (s *Server) sendError(reqType, msg string) {
	s.encoder.Encode(Response{
		Success: false,
		Type:    reqType,
		Error:   msg,
	})
}
