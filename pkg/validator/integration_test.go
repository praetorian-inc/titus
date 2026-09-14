// pkg/validator/integration_test.go
package validator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/llm"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_LLMVerifierUpgradesUndetermined(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"unknown","message":"unrecognized key format"}`))
	}))
	defer apiSrv.Close()

	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{
				"type": "text",
				"text": `{"status":"valid","confidence":0.85,"reason":"response body shows the key was accepted"}`,
			}},
			"model": "claude-haiku-4-5-20251001",
			"usage": map[string]any{"input_tokens": 100, "output_tokens": 50},
		})
	}))
	defer llmSrv.Close()

	undeterminedValidator := &staticValidator{
		result: &types.ValidationResult{
			Status:     types.StatusUndetermined,
			Confidence: 0.5,
			Message:    "ambiguous response",
			ResponseMeta: &types.ResponseMeta{
				StatusCode: 200,
				Body:       []byte(`{"status":"unknown"}`),
				URL:        apiSrv.URL,
			},
		},
	}
	engine := NewEngine(1, undeterminedValidator)

	llmClient, err := llm.NewClient("anthropic", "test-key", "claude-haiku-4-5-20251001",
		llm.WithBaseURL(llmSrv.URL))
	require.NoError(t, err)

	verifier := NewLLMVerifier(engine, llmClient, 256, 100)

	match := &types.Match{
		RuleID: "test.1",
		Groups: [][]byte{[]byte("my-secret-key")},
		Snippet: types.Snippet{
			Before:   []byte("API_KEY="),
			Matching: []byte("my-secret-key"),
			After:    []byte("\n"),
		},
	}

	result, err := verifier.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status, "LLM should upgrade undetermined to valid")
	assert.Contains(t, result.Message, "LLM")
}
