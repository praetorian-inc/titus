package serve

import (
	"bufio"
	"context"
	"encoding/json"
	"io"

	"github.com/praetorian-inc/titus/pkg/scanner"
)

// Version is the server protocol version
const Version = "1.0.0"

// Server manages the streaming scanner
type Server struct {
	core    *scanner.Core
	encoder *json.Encoder
	decoder *json.Decoder
}

// NewServer creates a new streaming server
func NewServer(core *scanner.Core, in io.Reader, out io.Writer) *Server {
	return &Server{
		core:    core,
		encoder: json.NewEncoder(out),
		decoder: json.NewDecoder(bufio.NewReader(in)),
	}
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
			if err == io.EOF {
				return nil
			}
			s.sendError("decode", err.Error())
			// After a decode error, the stream is likely corrupted,
			// but we continue to allow context cancellation
			return nil
		case req := <-reqChan:
			switch req.Type {
			case "scan":
				s.handleScan(req.Payload)
			case "scan_batch":
				s.handleScanBatch(req.Payload)
			case "close":
				return nil
			default:
				s.sendError("unknown", "unknown request type: "+req.Type)
			}
		}
	}
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

func (s *Server) sendError(reqType, msg string) {
	s.encoder.Encode(Response{
		Success: false,
		Type:    reqType,
		Error:   msg,
	})
}
