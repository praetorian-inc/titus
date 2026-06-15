package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	_ = pw.Close()

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

func TestServer_ScanPath(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	dir := t.TempDir()
	secret := "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.ini"), []byte(secret), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing here"), 0644))

	request := fmt.Sprintf(`{"type":"scan_path","payload":{"path":%q}}`, dir) + "\n"
	in := strings.NewReader(request)
	out := &bytes.Buffer{}

	srv := NewServer(core, in, out)
	err = srv.Run(context.Background())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	// ready + at least one result + done
	require.GreaterOrEqual(t, len(lines), 3)

	var results []Response
	var done Response
	for _, line := range lines[1:] {
		var resp Response
		require.NoError(t, json.Unmarshal([]byte(line), &resp))
		if resp.Type == "scan_path_result" {
			results = append(results, resp)
		} else if resp.Type == "scan_path_done" {
			done = resp
		}
	}

	require.NotEmpty(t, results, "expected at least one scan_path_result")
	assert.True(t, done.Success)
	assert.Equal(t, "scan_path_done", done.Type)

	var doneData ScanDoneData
	require.NoError(t, json.Unmarshal(done.Data, &doneData))
	assert.Equal(t, 2, doneData.TotalBlobs)
	assert.GreaterOrEqual(t, doneData.TotalMatches, 1)
}

func TestServer_ScanPath_EmptyDir(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	dir := t.TempDir()

	request := fmt.Sprintf(`{"type":"scan_path","payload":{"path":%q}}`, dir) + "\n"
	in := strings.NewReader(request)
	out := &bytes.Buffer{}

	srv := NewServer(core, in, out)
	err = srv.Run(context.Background())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2) // ready + done

	var resp Response
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &resp))
	assert.True(t, resp.Success)
	assert.Equal(t, "scan_path_done", resp.Type)

	var doneData ScanDoneData
	require.NoError(t, json.Unmarshal(resp.Data, &doneData))
	assert.Equal(t, 0, doneData.TotalBlobs)
	assert.Equal(t, 0, doneData.TotalMatches)
}

func TestServer_ScanGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "command %v failed: %s", args, string(out))
	}

	run("git", "init")
	run("git", "config", "user.email", "test@test.com")
	run("git", "config", "user.name", "Test")
	secret := "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.ini"), []byte(secret), 0644))
	run("git", "add", ".")
	run("git", "commit", "-m", "initial")

	request := fmt.Sprintf(`{"type":"scan_git","payload":{"path":%q}}`, dir) + "\n"
	in := strings.NewReader(request)
	out := &bytes.Buffer{}

	srv := NewServer(core, in, out)
	err = srv.Run(context.Background())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.GreaterOrEqual(t, len(lines), 3)

	var results []Response
	var done Response
	for _, line := range lines[1:] {
		var resp Response
		require.NoError(t, json.Unmarshal([]byte(line), &resp))
		if resp.Type == "scan_git_result" {
			results = append(results, resp)
		} else if resp.Type == "scan_git_done" {
			done = resp
		}
	}

	require.NotEmpty(t, results, "expected at least one scan_git_result")
	assert.True(t, done.Success)

	var doneData ScanDoneData
	require.NoError(t, json.Unmarshal(done.Data, &doneData))
	assert.GreaterOrEqual(t, doneData.TotalMatches, 1)
	assert.GreaterOrEqual(t, doneData.TotalBlobs, 1)
}

func TestServer_ScanGit_InvalidPath(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	request := `{"type":"scan_git","payload":{"path":"/nonexistent/path"}}` + "\n"
	in := strings.NewReader(request)
	out := &bytes.Buffer{}

	srv := NewServer(core, in, out)
	err = srv.Run(context.Background())
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.GreaterOrEqual(t, len(lines), 2)

	var resp Response
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &resp))
	assert.False(t, resp.Success)
	assert.Equal(t, "scan_git", resp.Type)
}
