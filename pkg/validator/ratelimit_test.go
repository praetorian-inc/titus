package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingValidator struct {
	calls atomic.Int32
}

func (v *countingValidator) Name() string                   { return "counting" }
func (v *countingValidator) CanValidate(ruleID string) bool { return ruleID == "test.1" }
func (v *countingValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	v.calls.Add(1)
	return types.NewValidationResult(types.StatusValid, 1.0, "ok"), nil
}

func TestEngine_WithRateLimit(t *testing.T) {
	cv := &countingValidator{}
	e := NewEngine(4, cv)
	e.SetRateLimit(2.0) // 2 requests/sec

	match := &types.Match{
		RuleID:  "test.1",
		Groups:  [][]byte{[]byte("secret123")},
		Snippet: types.Snippet{Matching: []byte("secret123")},
	}

	start := time.Now()
	results := make([]<-chan *types.ValidationResult, 4)
	for i := 0; i < 4; i++ {
		m := &types.Match{
			RuleID:  "test.1",
			Groups:  [][]byte{[]byte("secret" + string(rune('a'+i)))},
			Snippet: types.Snippet{Matching: []byte("secret" + string(rune('a'+i)))},
		}
		results[i] = e.ValidateAsync(context.Background(), m)
	}
	for _, ch := range results {
		r := <-ch
		require.NotNil(t, r)
	}
	elapsed := time.Since(start)
	_ = match
	assert.GreaterOrEqual(t, elapsed, 1*time.Second, "rate limit should throttle 4 requests at 2/sec")
}

func TestEngine_WithBackoff(t *testing.T) {
	bc := NewBackoffController(3, 100*time.Millisecond, 1*time.Second)
	cv := &countingValidator{}
	e := NewEngine(4, cv)
	e.SetBackoff(bc)
	assert.NotNil(t, e.backoff)
}

func TestEngine_SetBackoffRetriesHTTPValidator(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	def := ValidatorDef{
		Name:    "retry-wrap",
		RuleIDs: []string{"test.1"},
		HTTP: HTTPDef{
			Method:       http.MethodGet,
			URL:          srv.URL,
			Auth:         AuthDef{Type: "none", SecretGroup: "secret"},
			SuccessCodes: []int{http.StatusOK},
		},
	}
	hv := NewHTTPValidator(def, srv.Client())
	e := NewEngine(1, hv)
	e.SetBackoff(NewBackoffController(100, time.Millisecond, time.Second))

	match := &types.Match{
		RuleID:      "test.1",
		NamedGroups: map[string][]byte{"secret": []byte("token")},
		Snippet:     types.Snippet{Matching: []byte("token")},
	}
	result, err := e.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, int32(2), calls.Load())
}

func TestEngine_DefaultNoRateLimit(t *testing.T) {
	cv := &countingValidator{}
	e := NewEngine(4, cv)

	match := &types.Match{
		RuleID:  "test.1",
		Groups:  [][]byte{[]byte("secret123")},
		Snippet: types.Snippet{Matching: []byte("secret123")},
	}

	start := time.Now()
	result, err := e.ValidateMatch(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}
