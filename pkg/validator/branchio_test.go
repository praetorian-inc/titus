// pkg/validator/branchio_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestBranchIOValidator_Name(t *testing.T) {
	v := NewBranchIOValidator()
	assert.Equal(t, "branchio", v.Name())
}

func TestBranchIOValidator_CanValidate(t *testing.T) {
	v := NewBranchIOValidator()
	assert.True(t, v.CanValidate("np.branchio.1"))
	assert.False(t, v.CanValidate("np.branchio.2"))
	assert.False(t, v.CanValidate("np.branchio.3"))
	assert.False(t, v.CanValidate("np.github.1"))
}

func TestBranchIOValidator_ExtractCredentials_SecretInBefore(t *testing.T) {
	v := NewBranchIOValidator()

	match := &types.Match{
		RuleID: "np.branchio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
		},
		Snippet: types.Snippet{
			Before:   []byte("BRANCH_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo"),
			Matching: []byte("BRANCH_KEY=key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
			After:    []byte(""),
		},
	}

	key, secret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt", key)
	assert.Equal(t, "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo", secret)
}

func TestBranchIOValidator_ExtractCredentials_SecretInAfter(t *testing.T) {
	v := NewBranchIOValidator()

	match := &types.Match{
		RuleID: "np.branchio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("BRANCH_KEY=key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
			After:    []byte("BRANCH_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo"),
		},
	}

	key, secret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt", key)
	assert.Equal(t, "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo", secret)
}

func TestBranchIOValidator_ExtractCredentials_SecretInMatching(t *testing.T) {
	v := NewBranchIOValidator()

	match := &types.Match{
		RuleID: "np.branchio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("BRANCH_KEY=key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt BRANCH_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo"),
			After:    []byte(""),
		},
	}

	key, secret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt", key)
	assert.Equal(t, "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo", secret)
}

func TestBranchIOValidator_ExtractCredentials_BranchKeySecretPattern(t *testing.T) {
	v := NewBranchIOValidator()

	match := &types.Match{
		RuleID: "np.branchio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
		},
		Snippet: types.Snippet{
			Before:   []byte("BRANCH_KEY_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo"),
			Matching: []byte("BRANCH_KEY=key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
			After:    []byte(""),
		},
	}

	key, secret, err := v.extractCredentials(match)
	assert.NoError(t, err)
	assert.Equal(t, "key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt", key)
	assert.Equal(t, "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo", secret)
}

func TestBranchIOValidator_ExtractCredentials_MissingKey(t *testing.T) {
	v := NewBranchIOValidator()

	match := &types.Match{
		RuleID:      "np.branchio.1",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before: []byte("BRANCH_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo"),
		},
	}

	key, secret, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key")
	assert.Empty(t, key)
	assert.Empty(t, secret)
}

func TestBranchIOValidator_ExtractCredentials_MissingSecret(t *testing.T) {
	v := NewBranchIOValidator()

	match := &types.Match{
		RuleID: "np.branchio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
		},
		Snippet: types.Snippet{
			Before:   []byte("some other content"),
			Matching: []byte("BRANCH_KEY=key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
			After:    []byte("more content"),
		},
	}

	key, secret, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial")
	assert.Contains(t, err.Error(), "branch secret")
	assert.Empty(t, key)
	assert.Empty(t, secret)
}

func TestBranchIOValidator_ExtractCredentials_NoNamedGroups(t *testing.T) {
	v := NewBranchIOValidator()

	match := &types.Match{
		RuleID:      "np.branchio.1",
		NamedGroups: nil,
	}

	key, secret, err := v.extractCredentials(match)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no named capture groups")
	assert.Empty(t, key)
	assert.Empty(t, secret)
}

func TestBranchIOValidator_Validate_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.URL.Query().Get("branch_secret"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewBranchIOValidatorWithClient(&http.Client{
		Transport: &branchIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.branchio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
		},
		Snippet: types.Snippet{
			Before: []byte("BRANCH_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt")
}

func TestBranchIOValidator_Validate_Invalid_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewBranchIOValidatorWithClient(&http.Client{
		Transport: &branchIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.branchio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
		},
		Snippet: types.Snippet{
			Before: []byte("BRANCH_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "401")
}

func TestBranchIOValidator_Validate_Invalid_BadRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	v := NewBranchIOValidatorWithClient(&http.Client{
		Transport: &branchIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.branchio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
		},
		Snippet: types.Snippet{
			Before: []byte("BRANCH_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "400")
}

func TestBranchIOValidator_Validate_Undetermined_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewBranchIOValidatorWithClient(&http.Client{
		Transport: &branchIOMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.branchio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
		},
		Snippet: types.Snippet{
			Before: []byte("BRANCH_SECRET=aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Equal(t, 0.5, result.Confidence)
	assert.Contains(t, result.Message, "500")
}

func TestBranchIOValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewBranchIOValidator()

	match := &types.Match{
		RuleID: "np.branchio.1",
		NamedGroups: map[string][]byte{
			"key": []byte("key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
		},
		Snippet: types.Snippet{
			Before:   []byte("no secret here"),
			Matching: []byte("BRANCH_KEY=key_live_kaFuWw8WvY7yn1d9yYiP8gokwqjV0Swt"),
			After:    []byte("or here"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

// branchIOMockTransport redirects requests to the mock server
type branchIOMockTransport struct {
	server *httptest.Server
}

func (t *branchIOMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
