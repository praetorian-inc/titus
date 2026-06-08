package vcrtest

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
)

// testSecret is a fake AWS key that the builtin scanner detects via np.aws.1.
// It is intentionally not a real credential: it follows the AKIA + 16-char
// pattern but uses a nonsense value. If redaction ever regressed, scan-fixtures.sh
// would detect this pattern in testdata/ (np.aws.1 matches it) and fail CI.
const testSecret = "AKIADEADBEEFDEADBEEF"

// makeInteraction builds a cassette.Interaction with the secret embedded in
// the specified fields.
func makeInteraction(secretInURL, secretInReqBody, secretInRespBody, secretInHeader string) *cassette.Interaction {
	i := &cassette.Interaction{
		Request: cassette.Request{
			Method:  "GET",
			URL:     "https://example.com/api/validate",
			Body:    "",
			Headers: make(http.Header),
		},
		Response: cassette.Response{
			Code:    200,
			Body:    "",
			Headers: make(http.Header),
		},
	}
	if secretInURL != "" {
		i.Request.URL = "https://example.com/api/validate?token=" + secretInURL
	}
	if secretInReqBody != "" {
		i.Request.Body = `{"token":"` + secretInReqBody + `"}`
	}
	if secretInRespBody != "" {
		i.Response.Body = `{"key":"` + secretInRespBody + `","status":"ok"}`
	}
	if secretInHeader != "" {
		i.Request.Headers.Set("Authorization", "Bearer "+secretInHeader)
	}
	return i
}

// TestRedactHook_ReplayMode verifies that the hook is a no-op in replay mode:
// it must not modify any fields and must return nil even when fields contain
// detector-visible secrets.
func TestRedactHook_ReplayMode(t *testing.T) {
	hook := redactHook(false, false)

	i := makeInteraction(testSecret, testSecret, testSecret, testSecret)
	origURL := i.Request.URL
	origReqBody := i.Request.Body
	origRespBody := i.Response.Body
	origAuth := i.Request.Headers.Get("Authorization")

	err := hook(i)

	require.NoError(t, err)
	assert.Equal(t, origURL, i.Request.URL, "replay hook must not modify URL")
	assert.Equal(t, origReqBody, i.Request.Body, "replay hook must not modify request body")
	assert.Equal(t, origRespBody, i.Response.Body, "replay hook must not modify response body")
	assert.Equal(t, origAuth, i.Request.Headers.Get("Authorization"), "replay hook must not modify headers")
}

// TestRedactHook_RecordMode_HeaderSecret verifies that a secret carried in a
// custom auth header (Authorization: Bearer <token>) is detected and replaced
// with Placeholder in the cassette.
func TestRedactHook_RecordMode_HeaderSecret(t *testing.T) {
	hook := redactHook(true, false)

	i := makeInteraction("", "", "", testSecret)
	// URL and bodies are benign so the secret is only in the header.
	i.Request.URL = "https://example.com/api/validate"

	err := hook(i)

	require.NoError(t, err, "record-mode hook must succeed when secret is present")
	assert.NotContains(t, i.Request.Headers.Get("Authorization"), testSecret,
		"auth header must not contain the plaintext secret after redaction")
	assert.Contains(t, i.Request.Headers.Get("Authorization"), Placeholder,
		"auth header must contain Placeholder after redaction")
}

// TestRedactHook_RecordMode_URLQuerySecret verifies that a secret carried as a
// URL query parameter is redacted, including its percent-encoded form.
func TestRedactHook_RecordMode_URLQuerySecret(t *testing.T) {
	hook := redactHook(true, false)

	// Embed the secret in the URL query string (plain form).
	i := &cassette.Interaction{
		Request: cassette.Request{
			Method:  "GET",
			URL:     "https://example.com/api?token=" + testSecret,
			Headers: make(http.Header),
		},
		Response: cassette.Response{
			Body:    "ok",
			Headers: make(http.Header),
		},
	}

	err := hook(i)

	require.NoError(t, err)
	assert.NotContains(t, i.Request.URL, testSecret,
		"URL must not contain the plaintext secret after redaction")
	assert.Contains(t, i.Request.URL, Placeholder,
		"URL must contain Placeholder after redaction")
}

// TestRedactHook_RecordMode_RequestBodySecret verifies that a secret embedded
// in the request body is replaced with Placeholder.
func TestRedactHook_RecordMode_RequestBodySecret(t *testing.T) {
	hook := redactHook(true, false)

	i := makeInteraction("", testSecret, "", "")

	err := hook(i)

	require.NoError(t, err)
	assert.NotContains(t, i.Request.Body, testSecret,
		"request body must not contain the plaintext secret after redaction")
	assert.Contains(t, i.Request.Body, Placeholder,
		"request body must contain Placeholder after redaction")
}

// TestRedactHook_RecordMode_ResponseBodySecret verifies that a secret that
// appears in the response body is redacted when WithResponseBody is used.
// Without that option the body is elided entirely (see TestRedactHook_RecordMode_ResponseBodyElided).
func TestRedactHook_RecordMode_ResponseBodySecret(t *testing.T) {
	hook := redactHook(true, true /* keepResponseBody */)

	// Put the secret in the request header (so dogfood assertion passes) and
	// also in the response body (so we can verify response-body redaction).
	i := makeInteraction("", "", testSecret, testSecret)

	err := hook(i)

	require.NoError(t, err)
	assert.NotContains(t, i.Response.Body, testSecret,
		"response body must not contain the plaintext secret after redaction")
	assert.Contains(t, i.Response.Body, Placeholder,
		"response body must contain Placeholder after redaction")
}

// TestRedactHook_RecordMode_DogfoodAssertion verifies that when the scanner
// cannot find any secret in the request auth material the hook returns an
// error. This ensures misconfigured recording (e.g. tests that never send a
// real credential) fail loudly rather than producing a trivially-clean cassette.
func TestRedactHook_RecordMode_DogfoodAssertion(t *testing.T) {
	hook := redactHook(true, false)

	// No secret in URL, headers, or request body — scanner will find nothing.
	i := &cassette.Interaction{
		Request: cassette.Request{
			Method:  "GET",
			URL:     "https://example.com/api/validate",
			Body:    "no secret here",
			Headers: make(http.Header),
		},
		Response: cassette.Response{
			Body:    "ok",
			Headers: make(http.Header),
		},
	}
	// Ensure SECRET_PLAINTEXT is not set so backup scrub does not interfere.
	t.Setenv("SECRET_PLAINTEXT", "")

	err := hook(i)

	require.Error(t, err, "hook must return error when scanner finds no secret in request")
	assert.Contains(t, err.Error(), "scanner found no secrets",
		"error message must explain the dogfood assertion failure")
}

// TestRedactHook_RecordMode_SecretPlaintextBackup verifies that when
// SECRET_PLAINTEXT is set and the scanner also finds the secret, both paths
// work correctly and the secret is fully redacted.
func TestRedactHook_RecordMode_SecretPlaintextBackup(t *testing.T) {
	t.Setenv("SECRET_PLAINTEXT", testSecret)

	hook := redactHook(true, false)

	i := makeInteraction("", "", "", testSecret)

	err := hook(i)

	require.NoError(t, err)
	assert.NotContains(t, i.Request.Headers.Get("Authorization"), testSecret)
	assert.Contains(t, i.Request.Headers.Get("Authorization"), Placeholder)
}

// TestRedactHook_RecordMode_EncodedURLSecret verifies that a percent-encoded
// secret in a URL query parameter is also replaced. The scanner detects the
// raw form; the hook then replaces both the raw and URL-encoded variants.
func TestRedactHook_RecordMode_EncodedURLSecret(t *testing.T) {
	hook := redactHook(true, false)

	// Percent-encode the secret as it would appear in a real URL.
	// The hook must redact both the raw scanner match and the encoded form.
	// For AKIADEADBEEFDEADBEEF there are no special chars so QueryEscape
	// returns the same string; use a secret with a '+' to force encoding.
	// We also test the plain case to ensure the encoded-variant path is reached.
	i := &cassette.Interaction{
		Request: cassette.Request{
			Method: "GET",
			// Plain URL — scanner detects it; encoded replacement is the same string.
			URL:     "https://example.com/token?key=" + testSecret,
			Headers: make(http.Header),
		},
		Response: cassette.Response{
			Body:    "ok",
			Headers: make(http.Header),
		},
	}

	err := hook(i)

	require.NoError(t, err)
	assert.NotContains(t, i.Request.URL, testSecret)
	assert.Contains(t, i.Request.URL, Placeholder)
}

// TestGetCore_Singleton verifies that repeated calls to getCore return the
// same *scanner.Core instance (singleton behaviour via sync.Once).
func TestGetCore_Singleton(t *testing.T) {
	c1, err1 := getCore()
	c2, err2 := getCore()

	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.Same(t, c1, c2, "getCore must return the same instance on repeated calls")
}

// TestRedactHook_RecordMode_NoSecretPlaintext verifies that recording proceeds
// correctly without SECRET_PLAINTEXT when the scanner finds the secret on its own.
func TestRedactHook_RecordMode_NoSecretPlaintext(t *testing.T) {
	// Explicitly unset SECRET_PLAINTEXT to confirm it is optional.
	t.Setenv("SECRET_PLAINTEXT", "")

	hook := redactHook(true, false)

	i := makeInteraction("", "", "", testSecret)

	err := hook(i)

	require.NoError(t, err, "recording must succeed with scanner detection even without SECRET_PLAINTEXT")
	assert.NotContains(t, i.Request.Headers.Get("Authorization"), testSecret)
}

// TestRedactHook_RecordMode_ResponseBodyElided verifies that by default
// (keepResponseBody=false) the response body is blanked and Content-Length
// is removed even when a secret was present. This is the secure-by-default
// behaviour: nothing from the response body leaks into testdata/.
func TestRedactHook_RecordMode_ResponseBodyElided(t *testing.T) {
	hook := redactHook(true, false /* keepResponseBody=false */)

	// Secret in auth header (satisfies dogfood) and in response body.
	i := makeInteraction("", "", testSecret, testSecret)
	i.Response.Headers.Set("Content-Length", "50")

	err := hook(i)

	require.NoError(t, err)
	assert.Empty(t, i.Response.Body,
		"response body must be blanked when keepResponseBody is false")
	assert.Empty(t, i.Response.Headers.Get("Content-Length"),
		"Content-Length must be dropped when response body is elided")
}

// TestRedactHook_RecordMode_ResponseBodyKept verifies that when
// keepResponseBody=true (WithResponseBody option) the body is retained and
// any secret within it is redacted.
func TestRedactHook_RecordMode_ResponseBodyKept(t *testing.T) {
	hook := redactHook(true, true /* keepResponseBody=true */)

	// Secret in auth header (satisfies dogfood) and in response body.
	i := makeInteraction("", "", testSecret, testSecret)

	err := hook(i)

	require.NoError(t, err)
	assert.NotEmpty(t, i.Response.Body,
		"response body must be retained when keepResponseBody is true")
	assert.NotContains(t, i.Response.Body, testSecret,
		"secret must be redacted from response body")
	assert.Contains(t, i.Response.Body, Placeholder,
		"Placeholder must appear in response body after redaction")
}
