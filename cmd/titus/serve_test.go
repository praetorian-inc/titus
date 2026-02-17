package main

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServeCommand_Exists(t *testing.T) {
	// Verify serve command is registered
	cmd, _, err := rootCmd.Find([]string{"serve"})
	assert.NoError(t, err)
	assert.NotNil(t, cmd)
	assert.Equal(t, "serve", cmd.Name())
}

func TestServeCommand_Integration(t *testing.T) {
	// Create pipe for input
	pr, pw := io.Pipe()

	// Capture output
	out := &bytes.Buffer{}

	// Create a fresh command instance for testing
	testCmd := &cobra.Command{
		Use:  "serve",
		RunE: runServe,
	}
	testCmd.SetIn(pr)
	testCmd.SetOut(out)
	testCmd.SetErr(out)

	done := make(chan error, 1)
	go func() {
		done <- testCmd.Execute()
	}()

	// Wait for ready signal
	time.Sleep(500 * time.Millisecond)

	// Send close command
	_, err := pw.Write([]byte(`{"type":"close","payload":{}}` + "\n"))
	require.NoError(t, err)
	pw.Close()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("command did not exit in time")
	}

	// Verify ready signal was sent
	assert.Contains(t, out.String(), `"type":"ready"`)
}
