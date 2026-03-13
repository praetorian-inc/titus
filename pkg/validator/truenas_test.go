// pkg/validator/truenas_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestTrueNASValidator_Name(t *testing.T) {
	v := NewTrueNASValidator()
	assert.Equal(t, "truenas", v.Name())
}

func TestTrueNASValidator_CanValidate(t *testing.T) {
	v := NewTrueNASValidator()
	assert.True(t, v.CanValidate("np.truenas.1"))
	assert.True(t, v.CanValidate("np.truenas.2"))
	assert.True(t, v.CanValidate("np.truenas.3"))
	assert.False(t, v.CanValidate("np.github.1"))
	assert.False(t, v.CanValidate("np.shopify.1"))
}

func TestTrueNASValidator_ExtractToken_FromNamedGroups(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID: "np.truenas.3",
		NamedGroups: map[string][]byte{
			"token": []byte("8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
		},
	}

	token := v.extractToken(match)
	assert.Equal(t, "8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu", token)
}

func TestTrueNASValidator_ExtractToken_FromGroups(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID: "np.truenas.1",
		Groups: [][]byte{
			[]byte("8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
		},
	}

	token := v.extractToken(match)
	assert.Equal(t, "8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu", token)
}

func TestTrueNASValidator_ExtractToken_Missing(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID:      "np.truenas.3",
		NamedGroups: map[string][]byte{},
	}

	token := v.extractToken(match)
	assert.Empty(t, token)
}

func TestTrueNASValidator_ExtractURL_FromEnvVar(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID: "np.truenas.3",
		Snippet: types.Snippet{
			Before:   []byte("TRUENAS_URL=https://192.168.1.50"),
			Matching: []byte("TRUENAS_API_KEY=8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
			After:    []byte(""),
		},
	}

	url := v.extractURL(match)
	assert.Equal(t, "https://192.168.1.50", url)
}

func TestTrueNASValidator_ExtractURL_FromHostEnvVar(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID: "np.truenas.3",
		Snippet: types.Snippet{
			Before:   []byte("TN_HOST=http://truenas.local:8080 "),
			Matching: []byte("TN_API_KEY=8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
			After:    []byte(""),
		},
	}

	url := v.extractURL(match)
	assert.Equal(t, "http://truenas.local:8080", url)
}

func TestTrueNASValidator_ExtractURL_FromAPIPath(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID: "np.truenas.2",
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte(`curl -X GET "https://10.0.0.5/api/v2.0/system/info" -H "Authorization: Bearer 8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"`),
			After:    []byte(""),
		},
	}

	url := v.extractURL(match)
	assert.Equal(t, "https://10.0.0.5", url)
}

func TestTrueNASValidator_ExtractURL_FromTrueNASHostname(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID: "np.truenas.3",
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("truenas_token=8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
			After:    []byte("server = https://my-truenas.local"),
		},
	}

	url := v.extractURL(match)
	assert.Equal(t, "https://my-truenas.local", url)
}

func TestTrueNASValidator_ExtractURL_FromIPAddress(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID: "np.truenas.3",
		Snippet: types.Snippet{
			Before:   []byte("# NAS at http://192.168.0.30"),
			Matching: []byte("TRUENAS_API_KEY=8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
			After:    []byte(""),
		},
	}

	url := v.extractURL(match)
	assert.Equal(t, "http://192.168.0.30", url)
}

func TestTrueNASValidator_ExtractURL_NotFound(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID: "np.truenas.3",
		Snippet: types.Snippet{
			Before:   []byte("# no URL here"),
			Matching: []byte("TRUENAS_API_KEY=8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
			After:    []byte("# nothing here either"),
		},
	}

	url := v.extractURL(match)
	assert.Empty(t, url)
}

func TestTrueNASValidator_Validate_NoToken(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID:      "np.truenas.3",
		NamedGroups: map[string][]byte{},
		Snippet: types.Snippet{
			Before:   []byte("TRUENAS_URL=https://192.168.1.50"),
			Matching: []byte(""),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "token")
}

func TestTrueNASValidator_Validate_NoURL(t *testing.T) {
	v := NewTrueNASValidator()

	match := &types.Match{
		RuleID: "np.truenas.3",
		NamedGroups: map[string][]byte{
			"token": []byte("8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# no URL"),
			Matching: []byte("TRUENAS_API_KEY=8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "URL not in context")
}

// truenasMockTransport redirects requests to the mock server.
type truenasMockTransport struct {
	server *httptest.Server
}

func (t *truenasMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}

func TestTrueNASValidator_Validate_ValidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/api/v2.0/system/info")
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"version":"TrueNAS-SCALE-24.04"}`))
	}))
	defer server.Close()

	v := NewTrueNASValidatorWithClient(&http.Client{
		Transport: &truenasMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.truenas.3",
		NamedGroups: map[string][]byte{
			"token": []byte("8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
		},
		Snippet: types.Snippet{
			Before:   []byte("TRUENAS_URL=https://192.168.1.50"),
			Matching: []byte("TRUENAS_API_KEY=8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Contains(t, result.Message, "192.168.1.50")
}

func TestTrueNASValidator_Validate_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewTrueNASValidatorWithClient(&http.Client{
		Transport: &truenasMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.truenas.3",
		NamedGroups: map[string][]byte{
			"token": []byte("8-invalidkey00000000000000000000000000000000000000000000000000000"),
		},
		Snippet: types.Snippet{
			Before:   []byte("TRUENAS_URL=https://192.168.1.50"),
			Matching: []byte("TRUENAS_API_KEY=8-invalidkey00000000000000000000000000000000000000000000000000000"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestTrueNASValidator_Validate_ForbiddenToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewTrueNASValidatorWithClient(&http.Client{
		Transport: &truenasMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.truenas.2",
		Groups: [][]byte{
			[]byte("8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte(`curl https://10.0.0.5/api/v2.0/system/info -H "Authorization: Bearer 8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"`),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestTrueNASValidator_Validate_UnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewTrueNASValidatorWithClient(&http.Client{
		Transport: &truenasMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.truenas.3",
		NamedGroups: map[string][]byte{
			"token": []byte("8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
		},
		Snippet: types.Snippet{
			Before:   []byte("TRUENAS_URL=https://192.168.1.50"),
			Matching: []byte("TRUENAS_API_KEY=8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
}

func TestTrueNASValidator_Validate_PartialCredentials_Rule1(t *testing.T) {
	v := NewTrueNASValidator()

	// WebSocket match with token but no URL in context
	match := &types.Match{
		RuleID: "np.truenas.1",
		Groups: [][]byte{
			[]byte("8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte(`{"params":["8-Lp22ov7halMBLUpG97Wg4y7fibQi3CW19VJiZcCu746zgCs0mdDdTCoOcpgEucgu"]}`),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "URL not in context")
}

func TestTrueNASValidator_ExtractURL_StripAPIPath(t *testing.T) {
	v := NewTrueNASValidator()

	// Verify that /api/v2.0 is stripped from the extracted URL before building the request
	match := &types.Match{
		RuleID: "np.truenas.2",
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte(`curl "https://nas.example.com/api/v2.0/device/get_info"`),
			After:    []byte(""),
		},
	}

	url := v.extractURL(match)
	assert.Equal(t, "https://nas.example.com", url)
}
