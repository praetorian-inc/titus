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
	_ = pw.Close()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("command did not exit in time")
	}

	// Verify ready signal was sent
	assert.Contains(t, out.String(), `"type":"ready"`)
}

func TestServeCommand_RulesExcludeDisablesRule(t *testing.T) {
	scan := func() string {
		pr, pw := io.Pipe()
		out := &bytes.Buffer{}
		cmd := &cobra.Command{Use: "serve", RunE: runServe}
		cmd.SetIn(pr)
		cmd.SetOut(out)

		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()

		time.Sleep(500 * time.Millisecond)
		_, err := pw.Write([]byte(`{"type":"scan","payload":{"content":"sk_live_dhhfUUyfrAace5dBAZ10JrAD","source":""}}` + "\n"))
		require.NoError(t, err)
		time.Sleep(500 * time.Millisecond)
		_, _ = pw.Write([]byte(`{"type":"close","payload":{}}` + "\n"))
		_ = pw.Close()
		require.NoError(t, <-done)
		return out.String()
	}

	original := serveRulesExclude
	defer func() { serveRulesExclude = original }()

	// Rule enabled: the value matches np.stripe.1.
	serveRulesExclude = ""
	assert.Contains(t, scan(), "np.stripe.1")

	// Rule excluded: the value no longer matches.
	serveRulesExclude = `^np\.stripe\.1$`
	assert.NotContains(t, scan(), "np.stripe.1")
}
