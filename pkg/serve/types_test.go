package serve

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequest_ScanUnmarshal(t *testing.T) {
	input := `{"type":"scan","payload":{"content":"secret=abc123","source":"test"}}`

	var req Request
	err := json.Unmarshal([]byte(input), &req)
	require.NoError(t, err)

	assert.Equal(t, "scan", req.Type)

	var payload ScanPayload
	err = json.Unmarshal(req.Payload, &payload)
	require.NoError(t, err)

	assert.Equal(t, "secret=abc123", payload.Content)
	assert.Equal(t, "test", payload.Source)
}

func TestResponse_Marshal(t *testing.T) {
	resp := Response{
		Success: true,
		Type:    "ready",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	assert.Contains(t, string(data), `"success":true`)
	assert.Contains(t, string(data), `"type":"ready"`)
}
