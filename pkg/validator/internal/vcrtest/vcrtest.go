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

// options holds per-cassette configuration for Client.
type options struct {
	// keepResponseBody controls whether the response body is persisted in the
	// cassette. Defaults to false (bodies are elided) to minimise cassette
	// attack surface. Only validators that inspect the response body need to opt
	// in via WithResponseBody.
	//
	// Default-elide rationale: most validators decide on HTTP status code alone,
	// so storing response bodies adds noise and a potential secret-leak surface
	// with no benefit. A body-matcher that forgets WithResponseBody will fail
	// loudly on replay (body is empty) rather than silently (secret in body).
	keepResponseBody bool

	// matcher overrides the default secretInsensitiveMatcher for the cassette.
	// Useful for the rare validator that routes by query string rather than path.
	matcher cassette.MatcherFunc

	// extraRedactions holds (old, new) string pairs applied during record mode
	// after all scanner-based redactions. Each old value is replaced with its
	// corresponding new value across every cassette field. Use this for
	// account-identifying (but non-secret) values like cluster endpoint hostnames
	// or cluster IDs that appear in the request URL and must not be committed to
	// testdata/ as-is.
	extraRedactions [][2]string
}

// Option is a functional option for Client.
type Option func(*options)

// WithResponseBody opts the cassette into persisting response bodies.
// Use this only for validators whose Match logic inspects the response body
// (i.e. those with SuccessBodyContains or FailureBodyContains set in their
// YAML definition). The body is still scanned and redacted before being
// written to the cassette.
//
// Without this option, response bodies are blanked in record mode and
// Content-Length is dropped, so nothing leaks into testdata/.
func WithResponseBody() Option {
	return func(o *options) {
		o.keepResponseBody = true
	}
}

// WithMatcher replaces the default secretInsensitiveMatcher for this cassette.
// Use when the validator routes to different backend endpoints based on query
// parameters (e.g. a single path but different resource IDs in the query).
// The provided matcher receives the live request and the recorded cassette
// request and should return true when they are logically equivalent.
func WithMatcher(fn cassette.MatcherFunc) Option {
	return func(o *options) {
		o.matcher = fn
	}
}

// WithExtraRedactions registers additional (old, new) string replacement pairs
// applied during record mode after scanner-based redaction. Each pair replaces
// every occurrence of old with new across the request URL, request body,
// response body (when kept), and all header values before the cassette is
// written to disk.
//
// Use this for account-identifying values that are NOT secrets but should not
// be committed to testdata/ in plain form — for example, a Kafka cluster
// endpoint hostname (pkc-xxx.confluent.cloud) or a cluster ID (lkc-yyy).
// Unlike the scanner-based redaction, these replacements are literal and
// deterministic: the caller controls both the value to scrub and the fixed
// placeholder to write instead, ensuring the cassette matcher can match the
// recorded cassette against replay requests that use the same placeholders.
func WithExtraRedactions(pairs ...[2]string) Option {
	return func(o *options) {
		o.extraRedactions = append(o.extraRedactions, pairs...)
	}
}

// Client returns an *http.Client bound to the named cassette.
// cassettePath is relative to the test file, e.g. "testdata/huggingface/valid".
// The recorder is stopped via t.Cleanup.
//
// By default, response bodies are elided from cassettes (see WithResponseBody).
// By default, request matching uses secretInsensitiveMatcher (see WithMatcher).
func Client(t *testing.T, cassettePath string, opts ...Option) *http.Client {
	t.Helper()

	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	matcherFn := cassette.MatcherFunc(secretInsensitiveMatcher)
	if o.matcher != nil {
		matcherFn = o.matcher
	}

	isRecording := os.Getenv("RECORD") == "1"
	mode := recorder.ModeReplayOnly
	if isRecording {
		mode = recorder.ModeRecordOnce
	}

	rec, err := recorder.New(
		cassettePath,
		recorder.WithMode(mode),
		recorder.WithSkipRequestLatency(true),
		recorder.WithHook(redactHookWithExtras(isRecording, o.keepResponseBody, o.extraRedactions), recorder.AfterCaptureHook),
		recorder.WithHook(minimizeInteraction, recorder.BeforeSaveHook),
		recorder.WithMatcher(matcherFn),
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
// It delegates to redactHookWithExtras with an empty extra-redaction set.
func redactHook(isRecording bool, keepResponseBody bool) recorder.HookFunc {
	return redactHookWithExtras(isRecording, keepResponseBody, nil)
}

// redactHookWithExtras returns an AfterCaptureHook that is mode-aware.
//
// In replay mode the hook is a no-op: no live network call was made so there
// is no live secret to redact, and mutating cassette interactions during replay
// would corrupt the round-trip.
//
// In record mode the hook:
//  1. Scans request auth material (URL + request headers + request body) for
//     secrets using the Titus scanner. Dogfood assertion: zero matches is fatal,
//     guarding against silent misconfiguration.
//  2. Scans response header VALUES for new secrets (a credential minted only into
//     a response header, e.g. Set-Cookie or X-Subject-Token, would otherwise
//     survive into the cassette). Response headers are always scanned.
//  3. If keepResponseBody is true, scans the response body for additional secrets;
//     if false, blanks the body and drops Content-Length (secure-by-default).
//  4. Redacts all detected secrets (and their URL-encoded variants) across all
//     text fields that are persisted.
//
// If SECRET_PLAINTEXT is set the hook also performs a backup literal scrub of
// the raw value and its URL-encoded form AFTER the dogfood assertion has already
// passed. It does not satisfy or bypass the assertion; it is an extra safety net
// for service-specific token formats the scanner's ruleset may not cover.
func redactHookWithExtras(isRecording bool, keepResponseBody bool, extras [][2]string) recorder.HookFunc {
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
		// Include all request headers in request auth material as "Name: Value" so
		// context-dependent rules (e.g. kingfisher.exa.1 which requires an x-api-key
		// keyword near the UUID) fire correctly. Scanning the bare header value alone
		// would miss those rules because the keyword context would be absent.
		for h, vals := range i.Request.Headers {
			for _, v := range vals {
				requestFields = append(requestFields, field{"request.header." + h, h + ": " + v})
			}
		}

		// scanAndCollect scans a field and returns all matched secret strings.
		//
		// It collects BOTH the full match (Snippet.Matching, which may include keyword
		// context like "x-api-key: <uuid>") AND each non-empty positional capture group
		// (Groups[i]). This is required for context-dependent rules (e.g. kingfisher.exa.1)
		// where detection fires on the contextual form but the actual secret is in a
		// capture group (the bare UUID). Including the capture group ensures redactIn
		// scrubs the bare secret from field values even though detection required context.
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
				// Also collect each non-empty capture group so the bare secret
				// (e.g. the UUID from "x-api-key: <uuid>") is included in the
				// redaction set even when detection required surrounding context.
				// All current rule capture groups are >= 8 chars (e.g. the Exa UUID is 36),
				// so no min-length guard is needed here; revisit if a rule introduces a
				// very short (1-2 char) capture group that could cause spurious ReplaceAll.
				for _, g := range m.Groups {
					if len(g) > 0 {
						secrets = append(secrets, string(g))
					}
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

		// Collect secrets from response headers. A credential minted only into a
		// response header (e.g. Set-Cookie, X-Subject-Token) would not be caught by
		// the dogfood assertion (which is REQUEST-only by design) and would survive
		// into the cassette if not explicitly scanned here.
		// Note: response headers are always scanned regardless of keepResponseBody;
		// even when the body is elided, response headers are persisted in the cassette.
		allSecrets := make([]string, len(requestSecrets))
		copy(allSecrets, requestSecrets)
		for h, vals := range i.Response.Headers {
			for _, v := range vals {
				secrets, scanErr := scanAndCollect(field{"response.header." + h, h + ": " + v})
				if scanErr != nil {
					return scanErr
				}
				allSecrets = append(allSecrets, secrets...)
			}
		}
		// Collect secrets from the response body only when it is kept.
		if keepResponseBody {
			secrets, scanErr := scanAndCollect(field{"response.body", i.Response.Body})
			if scanErr != nil {
				return scanErr
			}
			allSecrets = append(allSecrets, secrets...)
		}

		// Backup scrub from SECRET_PLAINTEXT if provided.
		if pt := os.Getenv("SECRET_PLAINTEXT"); pt != "" {
			allSecrets = append(allSecrets, pt)
		}

		// Elide response body if not needed (secure-by-default).
		if !keepResponseBody {
			i.Response.Body = ""
			i.Response.Headers.Del("Content-Length")
		}

		// Perform all redactions across every text field that is kept.
		for _, secret := range allSecrets {
			i.Request.URL = redactIn(i.Request.URL, secret)
			i.Request.Body = redactIn(i.Request.Body, secret)
			if keepResponseBody {
				i.Response.Body = redactIn(i.Response.Body, secret)
			}
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

		// Apply extra (old, new) replacements: account-identifying values such as
		// cluster endpoint hostnames or cluster IDs that are not secrets but must
		// not be committed to testdata/ in plain form. These replacements happen
		// AFTER scanner-based redaction and are applied directly to all kept fields,
		// using the caller-supplied replacement string (not Placeholder).
		for _, pair := range extras {
			old, newVal := pair[0], pair[1]
			if old == "" {
				continue
			}
			i.Request.URL = strings.ReplaceAll(i.Request.URL, old, newVal)
			i.Request.Body = strings.ReplaceAll(i.Request.Body, old, newVal)
			if keepResponseBody {
				i.Response.Body = strings.ReplaceAll(i.Response.Body, old, newVal)
			}
			for h, vals := range i.Request.Headers {
				for idx, v := range vals {
					i.Request.Headers[h][idx] = strings.ReplaceAll(v, old, newVal)
				}
			}
			for h, vals := range i.Response.Headers {
				for idx, v := range vals {
					i.Response.Headers[h][idx] = strings.ReplaceAll(v, old, newVal)
				}
			}
		}

		return nil
	}
}

// minimizeInteraction is a BeforeSaveHook that strips all request and response
// headers and zeroes the response duration from each interaction before the
// cassette is written to disk.
//
// The validator replayer reads ONLY the response status code (and optionally the
// body when WithResponseBody is used); it never inspects any header. The request
// matcher secretInsensitiveMatcher compares only method, host, path, and query —
// never headers. Storing headers therefore adds noise and a pointless attack
// surface without providing any replay benefit.
//
// This hook fires in RECORD mode only (BeforeSaveHook does not execute during
// replay), so the running cassette replay is unaffected by this transformation.
func minimizeInteraction(i *cassette.Interaction) error {
	i.Request.Headers = nil
	i.Response.Headers = nil
	i.Response.Duration = 0
	i.Request.ContentLength = int64(len(i.Request.Body))
	i.Response.ContentLength = int64(len(i.Response.Body))
	// Blank the host field: go-vcr persists request.host separately from
	// request.url. The field is redundant for matching (secretInsensitiveMatcher
	// derives the host from url.Parse(i.URL).Host, not from i.Request.Host) and
	// can carry account-identifying cluster hostnames that must not be committed.
	i.Request.Host = ""
	return nil
}

// secretInsensitiveMatcher matches a live request against a recorded one by
// comparing HTTP method, host, URL path, and raw query string.
//
// Matching on query is safe with secret redaction: in record mode the hook
// replaces every detected secret token with Placeholder in the cassette URL,
// and the test passes Placeholder as the token value during replay, so live and
// cassette query strings agree. A stray UN-redacted secret in the query causes
// a replay MISS, surfacing the problem instead of silently hiding it.
//
// Previous behaviour matched path only, which (a) could mask a leaked secret
// in the query string and (b) broke validators that hit the same path multiple
// times with different queries.
//
// Use WithMatcher to override this behaviour for the rare case where routing is
// determined by query parameters that should not be compared literally.
func secretInsensitiveMatcher(r *http.Request, i cassette.Request) bool {
	iu, err := url.Parse(i.URL)
	if err != nil {
		// Fallback: compare raw URL strings on parse failure.
		return r.Method == i.Method && r.URL.String() == i.URL
	}
	return r.Method == i.Method &&
		r.URL.Host == iu.Host &&
		r.URL.Path == iu.Path &&
		r.URL.RawQuery == iu.RawQuery
}
