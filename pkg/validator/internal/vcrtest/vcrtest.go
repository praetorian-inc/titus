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
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

// Placeholder is substituted for the real secret in cassettes and MUST be the
// same value the test feeds into the validator Match, so replay matching works
// even when the secret appears in the URL or body.
const Placeholder = "REDACTED_SECRET"

// Client returns an *http.Client bound to the named cassette and a cleanup that
// stops the recorder. cassettePath is relative to the test file, e.g.
// "testdata/huggingface/valid".
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
// In replay mode the hook only scrubs known secret-bearing headers; there is
// no live secret to redact from URLs or bodies because no real HTTP call was
// made to the service.
//
// In record mode the hook additionally scrubs URLs, request bodies, and
// response bodies using the value of SECRET_PLAINTEXT. If that env var is
// empty when recording, the hook returns an error so the recorder fails fast
// rather than writing a cassette that may contain a plaintext credential.
// Always set SECRET_PLAINTEXT when running with RECORD=1:
//
//	SECRET_PLAINTEXT=<key> RECORD=1 make record-fixtures SVC=<service>
func redactHook(isRecording bool) recorder.HookFunc {
	return func(i *cassette.Interaction) error {
		// Header scrubbing is unconditional: safe in both modes and catches
		// headers that go-vcr captures even during replay (e.g. forwarded
		// request headers set by the test).
		for _, h := range []string{
			"Authorization", "Private-Token", "X-Vault-Token",
			"Api-Key", "X-Api-Key", "Cookie", "Proxy-Authorization",
		} {
			if _, ok := i.Request.Headers[h]; ok {
				i.Request.Headers.Set(h, "REDACTED")
			}
		}
		// Response headers that may echo identity.
		i.Response.Headers.Del("Set-Cookie")

		if !isRecording {
			// Replay mode: no live network call happened, nothing else to scrub.
			return nil
		}

		// Record mode: the raw secret may appear in the URL, request body, or
		// response body. Require SECRET_PLAINTEXT so we can scrub it.
		pt := os.Getenv("SECRET_PLAINTEXT")
		if pt == "" {
			return fmt.Errorf("vcrtest: SECRET_PLAINTEXT must be set when recording " +
				"(RECORD=1 SECRET_PLAINTEXT=<key> make record-fixtures SVC=<service>)")
		}
		i.Request.URL = strings.ReplaceAll(i.Request.URL, pt, Placeholder)
		i.Request.Body = strings.ReplaceAll(i.Request.Body, pt, Placeholder)
		i.Response.Body = strings.ReplaceAll(i.Response.Body, pt, Placeholder)
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
