package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_SendsReadyOnStart(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	in := strings.NewReader("")
	out := &bytes.Buffer{}

	srv := NewServer(core, in, out)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately to exit after ready

	_ = srv.Run(ctx)

	// Parse first line as ready message
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.NotEmpty(t, lines)

	var resp Response
	err = json.Unmarshal([]byte(lines[0]), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Success)
	assert.Equal(t, "ready", resp.Type)
}

func TestServer_Scan(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	// Input: scan request
	request := `{"type":"scan","payload":{"content":"AKIAIOSFODNN7EXAMPLE","source":"test"}}` + "\n"
	in := strings.NewReader(request)
	out := &bytes.Buffer{}

	srv := NewServer(core, in, out)
	err = srv.Run(context.Background())
	require.NoError(t, err) // Should exit cleanly on EOF

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2) // ready + scan response

	var resp Response
	err = json.Unmarshal([]byte(lines[1]), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Success)
	assert.Equal(t, "scan", resp.Type)
}

func TestServer_GracefulShutdownOnContext(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	// Slow reader that blocks
	pr, pw := io.Pipe()
	out := &bytes.Buffer{}

	srv := NewServer(core, pr, out)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error)
	go func() {
		done <- srv.Run(ctx)
	}()

	// Wait for ready signal
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	cancel()
	pw.Close()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestServer_ScanBatch(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	request := `{"type":"scan_batch","payload":{"items":[{"source":"s1","content":"test1"},{"source":"s2","content":"AKIAIOSFODNN7EXAMPLE"}]}}` + "\n"
	in := strings.NewReader(request)
	out := &bytes.Buffer{}

	srv := NewServer(core, in, out)
	err = srv.Run(context.Background())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2)

	var resp Response
	err = json.Unmarshal([]byte(lines[1]), &resp)
	require.NoError(t, err)

	assert.True(t, resp.Success)
	assert.Equal(t, "scan_batch", resp.Type)
}

func TestServer_CloseCommand(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	request := `{"type":"close","payload":{}}` + "\n"
	in := strings.NewReader(request)
	out := &bytes.Buffer{}

	srv := NewServer(core, in, out)
	err = srv.Run(context.Background())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 1) // Only ready signal
}

func TestServer_UnknownCommand(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	request := `{"type":"invalid","payload":{}}` + "\n"
	in := strings.NewReader(request)
	out := &bytes.Buffer{}

	srv := NewServer(core, in, out)
	_ = srv.Run(context.Background())

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2)

	var resp Response
	_ = json.Unmarshal([]byte(lines[1]), &resp)

	assert.False(t, resp.Success)
	assert.Contains(t, resp.Error, "unknown request type")
}

func TestServer_MalformedJSON(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	request := `{invalid json}` + "\n"
	in := strings.NewReader(request)
	out := &bytes.Buffer{}

	srv := NewServer(core, in, out)
	_ = srv.Run(context.Background())

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.GreaterOrEqual(t, len(lines), 2)

	var resp Response
	_ = json.Unmarshal([]byte(lines[1]), &resp)

	assert.False(t, resp.Success)
	assert.Equal(t, "decode", resp.Type)
}
