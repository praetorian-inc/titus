// Package vcrtest provides a go-vcr backed *http.Client for validator tests.
// Replay by default (CI-safe, no network). Set RECORD=1 to capture against the
// real service. Cassettes live next to the test under testdata/<service>/<name>.
package vcrtest

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/praetorian-inc/titus/pkg/scanner"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

// Placeholder is substituted for the real secret in cassettes and MUST be the
// same value the test feeds into the validator Match, so replay matching works
// even when the secret appears in the URL or body.
const Placeholder = "REDACTED_SECRET"

// coreOnce guards the single process-level scanner.Core instance.
// Rule compilation (Hyperscan pattern compilation) is expensive; we pay the
// cost once per process and reuse the result for every cassette interaction.
var (
	coreOnce    sync.Once
	sharedCore  *scanner.Core
	coreInitErr error
)

// getCore returns the lazily-initialised builtin scanner, or an error if
// rule compilation failed. Thread-safe via sync.Once.
func getCore() (*scanner.Core, error) {
	coreOnce.Do(func() {
		sharedCore, coreInitErr = scanner.NewCore("builtin", scanner.NoopLogger{})
	})
	return sharedCore, coreInitErr
}

// Client returns an *http.Client bound to the named cassette.
// cassettePath is relative to the test file, e.g. "testdata/huggingface/valid".
// The recorder is stopped via t.Cleanup.
func Client(t *testing.T, cassettePath string) *http.Client {
	t.Helper()

	isRecording := os.Getenv("RECORD") == "1"
	mode := recorder.ModeReplayOnly
	if isRecording {
		mode = recorder.ModeRecordOnce
	}

	rec, err := recorder.New(
		cassettePath,
		recorder.WithMode(mode),
		recorder.WithSkipRequestLatency(true),
		recorder.WithHook(redactHook(isRecording), recorder.AfterCaptureHook),
		recorder.WithMatcher(secretInsensitiveMatcher),
	)
	if err != nil {
		t.Fatalf("vcrtest: new recorder: %v", err)
	}

	t.Cleanup(func() {
		if err := rec.Stop(); err != nil {
			t.Errorf("vcrtest: stop recorder: %v", err)
		}
	})

	return rec.GetDefaultClient()
}

// redactHook returns an AfterCaptureHook that is mode-aware.
//
// In replay mode the hook is a no-op: no live network call was made so there
// is no live secret to redact, and mutating cassette interactions during replay
// would corrupt the round-trip.
//
// In record mode the hook uses the Titus scanner (dogfood) to detect secrets
// in every text field of the interaction and replaces each detected token with
// Placeholder. URL-encoded variants of each token are also replaced so that
// query-string secrets do not survive encoding.
//
// Dogfood assertion: if the scanner finds zero matches across all request auth
// material (URL + request headers + request body), the hook returns an error
// so the recorder refuses to write the cassette. This guards against silent
// misconfiguration where the secret was never sent and the cassette would be
// trivially "clean" but also useless.
//
// If SECRET_PLAINTEXT is set the hook also performs a backup literal scrub of
// the raw value and its URL-encoded form AFTER the dogfood assertion has already
// passed. It does not satisfy or bypass the assertion; it is an extra safety net
// for service-specific token formats the scanner's ruleset may not cover.
func redactHook(isRecording bool) recorder.HookFunc {
	return func(i *cassette.Interaction) error {
		if !isRecording {
			// Replay mode: no-op.
			return nil
		}

		core, err := getCore()
		if err != nil {
			return fmt.Errorf("vcrtest: scanner init failed: %w", err)
		}

		// Collect all text fields to scan. We track which fields belong to
		// the "request auth material" for the dogfood assertion separately.
		type field struct {
			name    string
			content string
		}
		requestFields := []field{
			{"request.url", i.Request.URL},
			{"request.body", i.Request.Body},
		}
		// Include all request header values in request auth material.
		for h, vals := range i.Request.Headers {
			for _, v := range vals {
				requestFields = append(requestFields, field{"request.header." + h, v})
			}
		}
		// NOTE: response headers are intentionally not scanned for new secrets.
		// A credential that appears only in a response header (e.g. X-Subject-Token,
		// Set-Cookie) would not be detected by the dogfood assertion and would not
		// be redacted below. This is a known gap tracked for a future follow-up.
		responseFields := []field{
			{"response.body", i.Response.Body},
		}

		// scanAndCollect scans a field and returns all matched secret strings.
		scanAndCollect := func(f field) ([]string, error) {
			result, scanErr := core.Scan(f.content, f.name)
			if scanErr != nil {
				return nil, fmt.Errorf("vcrtest: scan %s: %w", f.name, scanErr)
			}
			var secrets []string
			for _, m := range result.Matches {
				if len(m.Snippet.Matching) > 0 {
					secrets = append(secrets, string(m.Snippet.Matching))
				}
			}
			return secrets, nil
		}

		// redactIn replaces a secret and its URL-encoded variants in s.
		redactIn := func(s, secret string) string {
			s = strings.ReplaceAll(s, secret, Placeholder)
			if enc := url.QueryEscape(secret); enc != secret {
				s = strings.ReplaceAll(s, enc, Placeholder)
			}
			if enc := url.PathEscape(secret); enc != secret {
				s = strings.ReplaceAll(s, enc, Placeholder)
			}
			return s
		}

		// Scan request auth material and enforce dogfood assertion.
		var requestSecrets []string
		for _, f := range requestFields {
			secrets, scanErr := scanAndCollect(f)
			if scanErr != nil {
				return scanErr
			}
			requestSecrets = append(requestSecrets, secrets...)
		}
		if len(requestSecrets) == 0 {
			return fmt.Errorf("vcrtest: scanner found no secrets in request auth material; " +
				"ensure the test uses a real (revoked) token and verify the scanner ruleset " +
				"covers the service's token format " +
				"(RECORD=1 SECRET_PLAINTEXT=<key> make record-fixtures SVC=<service>)")
		}

		// Collect secrets from response fields as well (they may differ from
		// those in the request, e.g. a refresh token returned in the body).
		allSecrets := make([]string, len(requestSecrets))
		copy(allSecrets, requestSecrets)
		for _, f := range responseFields {
			secrets, scanErr := scanAndCollect(f)
			if scanErr != nil {
				return scanErr
			}
			allSecrets = append(allSecrets, secrets...)
		}

		// Backup scrub from SECRET_PLAINTEXT if provided.
		if pt := os.Getenv("SECRET_PLAINTEXT"); pt != "" {
			allSecrets = append(allSecrets, pt)
		}

		// Perform all redactions across every text field.
		for _, secret := range allSecrets {
			i.Request.URL = redactIn(i.Request.URL, secret)
			i.Request.Body = redactIn(i.Request.Body, secret)
			i.Response.Body = redactIn(i.Response.Body, secret)
			for h, vals := range i.Request.Headers {
				for idx, v := range vals {
					i.Request.Headers[h][idx] = redactIn(v, secret)
				}
			}
			for h, vals := range i.Response.Headers {
				for idx, v := range vals {
					i.Response.Headers[h][idx] = redactIn(v, secret)
				}
			}
		}

		return nil
	}
}

// secretInsensitiveMatcher matches a live request against a recorded one by
// comparing HTTP method and URL path only.
//
// This is intentionally loose: validators that pass the secret as a query
// parameter or in the body will use Placeholder as the token value during
// replay, so the live URL and cassette URL differ in the query string.
// Matching on method+path ensures those requests still replay correctly.
//
// NOTE: validators that use query parameters for *routing* (i.e. different
// paths are chosen based on the secret value) cannot be matched by this
// default matcher and need a per-cassette custom matcher.
func secretInsensitiveMatcher(r *http.Request, i cassette.Request) bool {
	return r.Method == i.Method && r.URL.Path == reqURLPath(i.URL)
}

// reqURLPath parses rawURL and returns just the path component.
func reqURLPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}
