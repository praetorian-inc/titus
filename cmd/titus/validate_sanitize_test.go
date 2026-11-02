package main

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// messageValidator returns a fixed result for every match, without network.
type messageValidator struct{ message string }

func (v messageValidator) Name() string            { return "fake" }
func (v messageValidator) CanValidate(string) bool { return true }
func (v messageValidator) Validate(context.Context, *types.Match) (*types.ValidationResult, error) {
	return types.NewValidationResult(types.StatusInvalid, 1.0, v.message), nil
}

// captureStderr redirects os.Stderr while fn runs and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	prev := os.Stderr
	os.Stderr = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	func() {
		defer func() { os.Stderr = prev }()
		fn()
	}()
	require.NoError(t, w.Close())
	return string(<-done)
}

func TestValidateMatches_VerboseSanitizesMessage(t *testing.T) {
	tests := []struct {
		name, message, want string
	}{
		{"hostile", "bad\x1b[2Jkey\x9b", `message=bad\x1b[2Jkey\x9b`},
		{"benign", "key revoked", "message=key revoked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := validator.NewEngine(1, messageValidator{message: tt.message})
			m := &types.Match{RuleID: "np.test.1", Snippet: types.Snippet{Matching: []byte("tok_" + tt.name)}}

			stderr := captureStderr(t, func() {
				validateMatches(context.Background(), engine, []*types.Match{m}, true)
			})

			require.NotNil(t, m.ValidationResult)
			assert.Equal(t, tt.message, m.ValidationResult.Message, "stored result keeps the raw message")
			assertNoTerminalControls(t, stderr)
			assert.Contains(t, stderr, tt.want+"\n")
		})
	}
}
