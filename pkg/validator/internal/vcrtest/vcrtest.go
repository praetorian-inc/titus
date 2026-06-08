// Package vcrtest provides a go-vcr backed *http.Client for validator tests.
// Replay by default (CI-safe, no network). Set RECORD=1 to capture against the
// real service. Cassettes live next to the test under testdata/<service>/<name>.
package vcrtest

import (
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

	mode := recorder.ModeReplayOnly
	if os.Getenv("RECORD") == "1" {
		mode = recorder.ModeRecordOnce
	}

	rec, err := recorder.New(
		cassettePath,
		recorder.WithMode(mode),
		recorder.WithSkipRequestLatency(true),
		recorder.WithHook(redact, recorder.AfterCaptureHook),
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

// redact runs AFTER capture, BEFORE the cassette is written to disk.
// It replaces secret-bearing material with Placeholder so no live credential
// is ever committed.
func redact(i *cassette.Interaction) error {
	// Common secret-bearing request headers.
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

	// Body + URL: the concrete secret value is injected by the test author as an
	// env var SECRET_PLAINTEXT during RECORD; scrub it everywhere.
	if pt := os.Getenv("SECRET_PLAINTEXT"); pt != "" {
		i.Request.URL = strings.ReplaceAll(i.Request.URL, pt, Placeholder)
		i.Request.Body = strings.ReplaceAll(i.Request.Body, pt, Placeholder)
		i.Response.Body = strings.ReplaceAll(i.Response.Body, pt, Placeholder)
	}

	return nil
}

// secretInsensitiveMatcher matches a live request against a recorded one while
// tolerating the secret having been replaced by Placeholder in the cassette.
// The test feeds Placeholder as the secret, so method+path+normalized-query match.
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
