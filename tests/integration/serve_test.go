//go:build integration

package integration

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getProjectRoot returns the path to the titus project root
func getProjectRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	// tests/integration/serve_test.go -> project root
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

func TestServeIntegration_ReadySignal(t *testing.T) {
	projectRoot := getProjectRoot()

	// Build titus first
	buildCmd := exec.Command("go", "build", "-o", "dist/titus", "./cmd/titus")
	buildCmd.Dir = projectRoot
	output, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "build failed: %s", string(output))

	// Start titus serve
	cmd := exec.Command(filepath.Join(projectRoot, "dist", "titus"), "serve")
	cmd.Dir = projectRoot

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	err = cmd.Start()
	require.NoError(t, err)

	defer func() {
		stdin.Close()
		cmd.Process.Kill()
	}()

	scanner := bufio.NewScanner(stdout)

	// Wait for ready with timeout
	readyChan := make(chan string, 1)
	go func() {
		if scanner.Scan() {
			readyChan <- scanner.Text()
		}
	}()

	select {
	case line := <-readyChan:
		var ready map[string]interface{}
		err = json.Unmarshal([]byte(line), &ready)
		require.NoError(t, err)
		assert.True(t, ready["success"].(bool))
		assert.Equal(t, "ready", ready["type"])
	case <-time.After(60 * time.Second):
		t.Fatal("timeout waiting for ready signal")
	}
}

func TestServeIntegration_ScanAWSKey(t *testing.T) {
	projectRoot := getProjectRoot()

	// Build titus first
	buildCmd := exec.Command("go", "build", "-o", "dist/titus", "./cmd/titus")
	buildCmd.Dir = projectRoot
	output, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "build failed: %s", string(output))

	// Start titus serve
	cmd := exec.Command(filepath.Join(projectRoot, "dist", "titus"), "serve")
	cmd.Dir = projectRoot

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	err = cmd.Start()
	require.NoError(t, err)

	defer func() {
		stdin.Close()
		cmd.Process.Kill()
	}()

	scanner := bufio.NewScanner(stdout)

	// Wait for ready
	require.True(t, waitForLine(scanner, 60*time.Second), "should receive ready signal")
	t.Log("Ready signal received")

	// Send scan request with AWS key
	request := `{"type":"scan","payload":{"content":"aws_access_key_id = AKIAIOSFODNN7EXAMPLE","source":"test-file.txt"}}` + "\n"
	_, err = stdin.Write([]byte(request))
	require.NoError(t, err)

	// Wait for scan response
	require.True(t, waitForLine(scanner, 30*time.Second), "should receive scan response")
	line := scanner.Text()

	var response map[string]interface{}
	err = json.Unmarshal([]byte(line), &response)
	require.NoError(t, err)

	assert.True(t, response["success"].(bool), "scan should succeed")
	assert.Equal(t, "scan", response["type"])

	// Verify we found a match (AWS key detection)
	data := response["data"].(map[string]interface{})
	matches := data["matches"].([]interface{})
	assert.NotEmpty(t, matches, "should find AWS key in content")

	t.Logf("Found %d matches", len(matches))
}

func TestServeIntegration_ScanBatch(t *testing.T) {
	projectRoot := getProjectRoot()

	// Build titus first
	buildCmd := exec.Command("go", "build", "-o", "dist/titus", "./cmd/titus")
	buildCmd.Dir = projectRoot
	output, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "build failed: %s", string(output))

	// Start titus serve
	cmd := exec.Command(filepath.Join(projectRoot, "dist", "titus"), "serve")
	cmd.Dir = projectRoot

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	err = cmd.Start()
	require.NoError(t, err)

	defer func() {
		stdin.Close()
		cmd.Process.Kill()
	}()

	scanner := bufio.NewScanner(stdout)

	// Wait for ready
	require.True(t, waitForLine(scanner, 60*time.Second), "should receive ready signal")

	// Send batch scan request
	request := `{"type":"scan_batch","payload":{"items":[{"source":"file1.txt","content":"no secrets here"},{"source":"file2.txt","content":"password=supersecret123"}]}}` + "\n"
	_, err = stdin.Write([]byte(request))
	require.NoError(t, err)

	// Wait for batch response
	require.True(t, waitForLine(scanner, 30*time.Second), "should receive batch response")
	line := scanner.Text()

	var response map[string]interface{}
	err = json.Unmarshal([]byte(line), &response)
	require.NoError(t, err)

	assert.True(t, response["success"].(bool), "batch scan should succeed")
	assert.Equal(t, "scan_batch", response["type"])
}

func TestServeIntegration_CloseCommand(t *testing.T) {
	projectRoot := getProjectRoot()

	// Build titus first
	buildCmd := exec.Command("go", "build", "-o", "dist/titus", "./cmd/titus")
	buildCmd.Dir = projectRoot
	output, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "build failed: %s", string(output))

	// Start titus serve
	cmd := exec.Command(filepath.Join(projectRoot, "dist", "titus"), "serve")
	cmd.Dir = projectRoot

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	err = cmd.Start()
	require.NoError(t, err)

	scanner := bufio.NewScanner(stdout)

	// Wait for ready
	require.True(t, waitForLine(scanner, 60*time.Second), "should receive ready signal")

	// Send close command
	_, err = stdin.Write([]byte(`{"type":"close","payload":{}}` + "\n"))
	require.NoError(t, err)

	// Wait for process to exit
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		assert.NoError(t, err, "process should exit cleanly")
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("process did not exit in time after close command")
	}
}

func waitForLine(scanner *bufio.Scanner, timeout time.Duration) bool {
	done := make(chan bool, 1)
	go func() {
		done <- scanner.Scan()
	}()

	select {
	case result := <-done:
		return result
	case <-time.After(timeout):
		return false
	}
}

// TestServeIntegration_MultipleScans tests that multiple scans work in sequence
func TestServeIntegration_MultipleScans(t *testing.T) {
	projectRoot := getProjectRoot()

	// Build titus first
	buildCmd := exec.Command("go", "build", "-o", "dist/titus", "./cmd/titus")
	buildCmd.Dir = projectRoot
	output, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "build failed: %s", string(output))

	// Start titus serve
	cmd := exec.Command(filepath.Join(projectRoot, "dist", "titus"), "serve")
	cmd.Dir = projectRoot

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	err = cmd.Start()
	require.NoError(t, err)

	defer func() {
		stdin.Close()
		cmd.Process.Kill()
	}()

	scanner := bufio.NewScanner(stdout)

	// Wait for ready
	require.True(t, waitForLine(scanner, 60*time.Second), "should receive ready signal")

	// Send multiple scan requests
	for i := 0; i < 5; i++ {
		request := `{"type":"scan","payload":{"content":"test content ` + string(rune('0'+i)) + `","source":"test"}}` + "\n"
		_, err = stdin.Write([]byte(request))
		require.NoError(t, err)

		require.True(t, waitForLine(scanner, 10*time.Second), "should receive scan response %d", i)
		line := scanner.Text()

		// Skip if it's a debug line
		if strings.Contains(line, `"debug"`) {
			i-- // retry this iteration
			continue
		}

		var response map[string]interface{}
		err = json.Unmarshal([]byte(line), &response)
		require.NoError(t, err)
		assert.True(t, response["success"].(bool), "scan %d should succeed", i)
	}

	t.Log("Successfully completed 5 sequential scans")
}
