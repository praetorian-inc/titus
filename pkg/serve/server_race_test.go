package serve

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServer_ScanBatch_RaceCondition tests that scan_batch responses are sent
// even when EOF arrives before the main loop processes the pending request.
// This test fails with the old implementation due to the race condition.
func TestServer_ScanBatch_RaceCondition(t *testing.T) {
	core, err := scanner.NewCore("builtin", nil)
	require.NoError(t, err)
	defer core.Close()

	// Run the test multiple times to trigger the race condition
	for i := range 10 {
		request := `{"type":"scan_batch","payload":{"items":[{"source":"s1","content":"test1"},{"source":"s2","content":"AKIAIOSFODNN7EXAMPLE"}]}}` + "\n"
		in := strings.NewReader(request)
		out := &strings.Builder{}

		srv := NewServer(core, in, out)
		err = srv.Run(context.Background())
		require.NoError(t, err)

		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		require.Len(t, lines, 2, "iteration %d: expected 2 lines (ready + scan_batch response), got %d", i, len(lines))

		var resp Response
		err = json.Unmarshal([]byte(lines[1]), &resp)
		require.NoError(t, err, "iteration %d: failed to unmarshal response", i)

		assert.True(t, resp.Success, "iteration %d: expected success", i)
		assert.Equal(t, "scan_batch", resp.Type, "iteration %d: expected scan_batch type", i)
	}
}
