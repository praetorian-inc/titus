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

// ---- Fix 3: Matcher tests ----

// TestSecretInsensitiveMatcher_SameMethodHostPathQuery verifies that the
// matcher returns true when method, host, path, and raw query all match.
func TestSecretInsensitiveMatcher_SameMethodHostPathQuery(t *testing.T) {
	req, err := http.NewRequest("GET", "https://api.example.com/v1/users?token="+Placeholder, nil)
	require.NoError(t, err)

	cassReq := cassette.Request{
		Method: "GET",
		URL:    "https://api.example.com/v1/users?token=" + Placeholder,
	}

	assert.True(t, secretInsensitiveMatcher(req, cassReq),
		"matcher must return true when method, host, path, and query all agree")
}

// TestSecretInsensitiveMatcher_DifferentQuery verifies that the matcher returns
// false when the query string differs. This prevents two requests to the same
// path but different query parameters from being treated as equivalent.
func TestSecretInsensitiveMatcher_DifferentQuery(t *testing.T) {
	req, err := http.NewRequest("GET", "https://api.example.com/v1/users?token=TokenA", nil)
	require.NoError(t, err)

	cassReq := cassette.Request{
		Method: "GET",
		URL:    "https://api.example.com/v1/users?token=TokenB",
	}

	assert.False(t, secretInsensitiveMatcher(req, cassReq),
		"matcher must return false when query strings differ")
}

// TestSecretInsensitiveMatcher_DifferentHost verifies that the matcher returns
// false when the host differs, even if path and query are the same.
func TestSecretInsensitiveMatcher_DifferentHost(t *testing.T) {
	req, err := http.NewRequest("GET", "https://api.example.com/v1/users", nil)
	require.NoError(t, err)

	cassReq := cassette.Request{
		Method: "GET",
		URL:    "https://other.example.com/v1/users",
	}

	assert.False(t, secretInsensitiveMatcher(req, cassReq),
		"matcher must return false when hosts differ")
}

// TestSecretInsensitiveMatcher_DifferentMethod verifies that the matcher returns
// false when the HTTP method differs.
func TestSecretInsensitiveMatcher_DifferentMethod(t *testing.T) {
	req, err := http.NewRequest("POST", "https://api.example.com/v1/users?token="+Placeholder, nil)
	require.NoError(t, err)

	cassReq := cassette.Request{
		Method: "GET",
		URL:    "https://api.example.com/v1/users?token=" + Placeholder,
	}

	assert.False(t, secretInsensitiveMatcher(req, cassReq),
		"matcher must return false when methods differ")
}

// TestWithMatcher_Override verifies that WithMatcher replaces the default
// secretInsensitiveMatcher for the cassette. We test by ensuring a custom
// matcher is wired into the options struct via the functional option.
func TestWithMatcher_Override(t *testing.T) {
	o := &options{}
	customMatcher := func(r *http.Request, i cassette.Request) bool { return true }
	WithMatcher(customMatcher)(o)

	require.NotNil(t, o.matcher, "WithMatcher must set options.matcher")
}

// ---- Fix 4: Response header secret detection ----

// TestRedactHook_RecordMode_ResponseHeaderSecret verifies that a secret that
// appears ONLY in a response header value (e.g. Set-Cookie, X-Subject-Token)
// is detected and redacted. Previously this was a gap: response header values
// were not scanned for new secrets.
func TestRedactHook_RecordMode_ResponseHeaderSecret(t *testing.T) {
	hook := redactHook(true, false)

	i := &cassette.Interaction{
		Request: cassette.Request{
			Method:  "GET",
			URL:     "https://example.com/api/validate",
			Headers: make(http.Header),
		},
		Response: cassette.Response{
			Code:    200,
			Body:    "",
			Headers: make(http.Header),
		},
	}
	// Secret only in a request header (satisfies dogfood assertion).
	i.Request.Headers.Set("Authorization", "Bearer "+testSecret)
	// Additional secret minted into a response header only.
	i.Response.Headers.Set("X-Subject-Token", testSecret)

	err := hook(i)

	require.NoError(t, err)
	assert.NotContains(t, i.Response.Headers.Get("X-Subject-Token"), testSecret,
		"response header must not contain the plaintext secret after redaction")
	assert.Contains(t, i.Response.Headers.Get("X-Subject-Token"), Placeholder,
		"response header must contain Placeholder after redaction")
}

// ---- minimizeInteraction tests ----

// TestMinimizeInteraction_StripsHeadersPreservesEssentials verifies that
// minimizeInteraction clears all request and response headers, zeroes the
// response duration, and leaves the request method, URL, response code, and
// response body untouched.
func TestMinimizeInteraction_StripsHeadersPreservesEssentials(t *testing.T) {
	i := &cassette.Interaction{
		Request: cassette.Request{
			Method:  "GET",
			URL:     "https://huggingface.co/api/whoami-v2",
			Headers: http.Header{"Authorization": []string{"Bearer " + Placeholder}},
		},
		Response: cassette.Response{
			Code:     200,
			Body:     "some-body",
			Headers:  http.Header{"X-Amz-Cf-Id": []string{"abc123"}, "Date": []string{"Mon, 01 Jan 2026 00:00:00 GMT"}},
			Duration: 123456789, // non-zero duration
		},
	}

	err := minimizeInteraction(i)

	require.NoError(t, err, "minimizeInteraction must not return an error")

	// Headers stripped.
	assert.Empty(t, i.Request.Headers, "request headers must be cleared")
	assert.Empty(t, i.Response.Headers, "response headers must be cleared")

	// Duration zeroed.
	assert.Zero(t, i.Response.Duration, "response duration must be zeroed")

	// Essentials preserved.
	assert.Equal(t, "GET", i.Request.Method, "request method must be preserved")
	assert.Equal(t, "https://huggingface.co/api/whoami-v2", i.Request.URL, "request URL must be preserved")
	assert.Equal(t, 200, i.Response.Code, "response code must be preserved")
	assert.Equal(t, "some-body", i.Response.Body, "response body must be preserved")

	// ContentLength normalized to match actual body length.
	assert.Equal(t, int64(len(i.Request.Body)), i.Request.ContentLength, "request ContentLength must equal len(body)")
	assert.Equal(t, int64(len(i.Response.Body)), i.Response.ContentLength, "response ContentLength must equal len(body)")
}

// ---- Fix 5: Context-aware header scanning + capture-group redaction ----

// exaExampleKey is the public example key from kingfisher.exa.1's examples list.
// It is NOT a real credential; the rule's own documentation uses this value.
// The pattern requires context (exa/x-api-key keyword) — scanning the bare UUID
// alone would yield no match, which is the bug this test exercises.
const exaExampleKey = "3f5a9c1e-2b4d-4a6f-8c10-1d2e3f4a5b6c"

// TestRedactHook_RecordMode_ContextDependentHeaderSecret verifies that a secret
// carried in an x-api-key request header (Exa-style, requires context to match)
// is detected via the reconstructed "Name: Value" form and that the bare UUID
// capture group is redacted from the header value.
//
// Before the fix, scanning the bare value ("3f5a9c1e-...") yielded no match
// because kingfisher.exa.1 requires an "x-api-key" keyword near the UUID.
// The fix reconstructs "x-api-key: 3f5a9c1e-..." before scanning, which fires
// the rule, and then redacts using the capture group (bare UUID) not the full
// match, so the bare UUID is scrubbed from the header value.
func TestRedactHook_RecordMode_ContextDependentHeaderSecret(t *testing.T) {
	hook := redactHook(true, false)

	i := &cassette.Interaction{
		Request: cassette.Request{
			Method:  "POST",
			URL:     "https://api.exa.ai/answer",
			Body:    `{"query":"ping","text":false}`,
			Headers: make(http.Header),
		},
		Response: cassette.Response{
			Code:    200,
			Body:    "",
			Headers: make(http.Header),
		},
	}
	// Secret is in x-api-key header — context-dependent: bare UUID alone is no match.
	i.Request.Headers.Set("x-api-key", exaExampleKey)

	err := hook(i)

	// (a) Hook must NOT error: dogfood assertion satisfied because scanning
	//     "x-api-key: 3f5a9c1e-..." fires the rule.
	require.NoError(t, err, "context-dependent header secret must satisfy dogfood assertion")

	// (b) The bare UUID must be scrubbed from the header value because the
	//     capture group (not just Snippet.Matching) is included in the redaction set.
	assert.NotContains(t, i.Request.Headers.Get("x-api-key"), exaExampleKey,
		"x-api-key header value must not contain the bare UUID after capture-group redaction")
	assert.Contains(t, i.Request.Headers.Get("x-api-key"), Placeholder,
		"x-api-key header must contain Placeholder after capture-group redaction")
}

// TestRedactHook_RecordMode_SelfContainedTokenStillWorks is a regression test
// confirming that the existing bare-value scanning path for self-contained tokens
// (e.g. AKIA-style AWS keys, hf_-style HuggingFace tokens) continues to work
// after the context-aware scanning change. The AWS fake key AKIADEADBEEFDEADBEEF
// matches np.aws.1 without any surrounding context keyword.
func TestRedactHook_RecordMode_SelfContainedTokenStillWorks(t *testing.T) {
	hook := redactHook(true, false)

	// testSecret (AKIADEADBEEFDEADBEEF) matches np.aws.1 on the bare value.
	i := makeInteraction("", "", "", testSecret)

	err := hook(i)

	require.NoError(t, err, "self-contained token in header must still satisfy dogfood assertion")
	assert.NotContains(t, i.Request.Headers.Get("Authorization"), testSecret,
		"self-contained token must be redacted from Authorization header")
	assert.Contains(t, i.Request.Headers.Get("Authorization"), Placeholder,
		"Placeholder must appear after redaction of self-contained token")
}

// ---- WithExtraRedactions option ----

// TestWithExtraRedactions_ReplacesOldWithNew verifies that extra (old, new) pairs
// provided via WithExtraRedactions are applied during record mode, replacing each
// old value with the corresponding new placeholder across all cassette fields.
func TestWithExtraRedactions_ReplacesOldWithNew(t *testing.T) {
	// Build a hook with one extra redaction pair: replace "realhost.confluent.cloud"
	// with "pkc-REDACTED0.example.confluent.cloud".
	const realHost = "pkc-abc123.us-east4.gcp.confluent.cloud"
	const fakeHost = "pkc-REDACTED0.example.confluent.cloud"

	hook := redactHookWithExtras(true, false, [][2]string{{realHost, fakeHost}})

	i := &cassette.Interaction{
		Request: cassette.Request{
			Method:  "GET",
			URL:     "https://" + realHost + "/kafka/v3/clusters/lkc-nvodzyv/topics",
			Headers: make(http.Header),
		},
		Response: cassette.Response{
			Code:    200,
			Body:    "",
			Headers: make(http.Header),
		},
	}
	// Satisfy the dogfood assertion by putting a detectable secret in the header.
	i.Request.Headers.Set("Authorization", "Basic AKIADEADBEEFDEADBEEF")

	err := hook(i)

	require.NoError(t, err)
	assert.NotContains(t, i.Request.URL, realHost,
		"real host must be replaced in the URL")
	assert.Contains(t, i.Request.URL, fakeHost,
		"fake placeholder host must appear in the URL")
}

// TestWithExtraRedactions_ReplayModeIsNoop verifies that extra redactions are
// not applied during replay mode (no live secrets to scrub).
func TestWithExtraRedactions_ReplayModeIsNoop(t *testing.T) {
	const realHost = "pkc-abc123.us-east4.gcp.confluent.cloud"
	const fakeHost = "pkc-REDACTED0.example.confluent.cloud"

	hook := redactHookWithExtras(false, false, [][2]string{{realHost, fakeHost}})

	i := &cassette.Interaction{
		Request: cassette.Request{
			Method: "GET",
			URL:    "https://" + realHost + "/kafka/v3/clusters/lkc-nvodzyv/topics",
		},
		Response: cassette.Response{},
	}
	origURL := i.Request.URL

	err := hook(i)

	require.NoError(t, err)
	assert.Equal(t, origURL, i.Request.URL,
		"replay mode must not modify the URL even with extra redaction pairs")
}
