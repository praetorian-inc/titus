package scoring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/praetorian-inc/titus/pkg/types"
)

type plaidHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// extractPlaidSecret extracts the Plaid secret from the match.
// Tries named group "token" first, falls back to positional group 0.
func extractPlaidSecret(m *types.Match) (string, bool) {
	if m == nil {
		return "", false
	}
	if v, ok := m.NamedGroups["token"]; ok && len(v) > 0 {
		return string(v), true
	}
	if len(m.Groups) > 0 && len(m.Groups[0]) > 0 {
		return string(m.Groups[0]), true
	}
	return "", false
}

var plaidClientIDRe = regexp.MustCompile(`(?i)["']?(?:plaid[_-]?)?client[_-]?id["']?\s*[:=]\s*["']?([a-z0-9]{24})\b`)

// extractPlaidClientID scans surrounding context for a co-located Plaid client ID.
func extractPlaidClientID(m *types.Match) (string, bool) {
	if m == nil {
		return "", false
	}
	// kingfisher.plaid.1 captures the client_id as a named group. Prefer it:
	// the group is the value the rule actually matched, whereas the context
	// scan below re-derives it with a second regex.
	if v, ok := m.NamedGroups["client_id"]; ok && len(v) > 0 {
		return string(v), true
	}
	for _, ctx := range [][]byte{m.Snippet.Before, m.Snippet.Matching, m.Snippet.After} {
		if sub := plaidClientIDRe.FindSubmatch(ctx); len(sub) > 1 {
			return string(sub[1]), true
		}
	}
	return "", false
}

type plaidInstitutionsReq struct {
	ClientID     string   `json:"client_id"`
	Secret       string   `json:"secret"` // #nosec G101 -- API request field, not a hardcoded credential
	Count        int      `json:"count"`
	Offset       int      `json:"offset"`
	CountryCodes []string `json:"country_codes"`
}

var plaidInvalidAPIKeys = []byte("INVALID_API_KEYS")

// The three Plaid hosts a secret can belong to. Named constants because the
// per-environment conditions and the revoked check must probe the SAME URLs:
// if they drifted apart, revoked-key would miss the cache and issue three
// extra requests per finding.
const (
	plaidEnvProduction  = "https://production.plaid.com/institutions/get"
	plaidEnvDevelopment = "https://development.plaid.com/institutions/get"
	plaidEnvSandbox     = "https://sandbox.plaid.com/institutions/get"
)

var plaidEnvironments = []string{plaidEnvProduction, plaidEnvDevelopment, plaidEnvSandbox}

// plaidEnvOutcome is the result of probing ONE environment with ONE credential
// pair. Exactly one of the three states holds: the environment accepted the
// credentials, explicitly rejected them with INVALID_API_KEYS, or could not be
// reached for a verdict.
type plaidEnvOutcome struct {
	valid    bool
	rejected bool
	err      error
}

// plaidProbeCache coalesces /institutions/get probes so that each
// (environment, credential) pair costs at most one request per scan.
//
// Without it a single finding costs up to six live authentication attempts:
// one per environment condition, plus three more inside revoked-key, which
// re-probes every environment. production.plaid.com would see the same
// credential twice. These are real auth attempts against the customer's Plaid
// account and appear in its audit log, so the duplication is not merely slow.
//
// Unreachable-environment outcomes are cached alongside verdicts -- the same
// choice condition_http.go makes for 429/5xx -- so a broken environment is not
// re-probed once per modifier. The error reaches the engine only on its first
// consumer: four modifiers each reporting one outage would be four warnings
// for a single failure.
type plaidProbeCache struct {
	mu      sync.Mutex
	entries map[string]*plaidCacheEntry
	group   singleflight.Group
}

type plaidCacheEntry struct {
	outcome  plaidEnvOutcome
	reported bool
}

func newPlaidProbeCache() *plaidProbeCache {
	return &plaidProbeCache{entries: make(map[string]*plaidCacheEntry)}
}

// plaidCacheKey hashes the credential pair so plaintext secrets never appear
// in map keys. The environment URL carries no secret and stays readable.
func plaidCacheKey(envURL, clientID, secret string) string {
	sum := sha256.Sum256([]byte(clientID + "\x00" + secret))
	return envURL + "\x00" + hex.EncodeToString(sum[:])
}

// probe returns the outcome for one environment, issuing at most one request
// per (environment, credential) pair. A nil cache probes directly, which is
// what unit tests constructing bare conditions rely on.
func (c *plaidProbeCache) probe(ctx context.Context, client plaidHTTPClient, envURL, clientID, secret string) plaidEnvOutcome {
	if c == nil {
		return plaidProbeEnv(ctx, client, envURL, clientID, secret)
	}
	key := plaidCacheKey(envURL, clientID, secret)

	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		out := entry.outcome
		if out.err != nil {
			if entry.reported {
				out.err = nil // already surfaced once; do not warn again
			}
			entry.reported = true
		}
		c.mu.Unlock()
		return out
	}
	c.mu.Unlock()

	v, _, _ := c.group.Do(key, func() (any, error) {
		out := plaidProbeEnv(ctx, client, envURL, clientID, secret)
		c.mu.Lock()
		c.entries[key] = &plaidCacheEntry{outcome: out, reported: out.err != nil}
		c.mu.Unlock()
		return out, nil
	})
	outcome, _ := v.(plaidEnvOutcome)
	return outcome
}

// plaidProbeEnv issues one /institutions/get request and classifies it.
//
// A rate limit, server error, transport failure or unreadable body is
// INCONCLUSIVE, not a rejection: reporting a live key as dead because Plaid was
// briefly unreachable is the worst outcome available here, so those return an
// error and leave the score alone.
func plaidProbeEnv(ctx context.Context, client plaidHTTPClient, envURL, clientID, secret string) plaidEnvOutcome {
	body, err := json.Marshal(plaidInstitutionsReq{
		ClientID:     clientID,
		Secret:       secret,
		Count:        1,
		Offset:       0,
		CountryCodes: []string{"US"},
	})
	if err != nil {
		return plaidEnvOutcome{err: fmt.Errorf("plaid: encode request: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", envURL, bytes.NewReader(body))
	if err != nil {
		return plaidEnvOutcome{err: fmt.Errorf("plaid: build request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return plaidEnvOutcome{err: fmt.Errorf("plaid %s: %w", envURL, classifyHTTPError(0, err))}
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return plaidEnvOutcome{err: fmt.Errorf("plaid %s: read response: %w", envURL, err)}
	}

	// An explicit INVALID_API_KEYS is a verdict at any status code.
	if bytes.Contains(respBody, plaidInvalidAPIKeys) {
		return plaidEnvOutcome{rejected: true}
	}
	if resp.StatusCode == http.StatusOK {
		return plaidEnvOutcome{valid: true}
	}
	if classified := classifyHTTPError(resp.StatusCode, nil); classified != nil {
		return plaidEnvOutcome{err: fmt.Errorf("plaid %s: %w", envURL, classified)}
	}
	return plaidEnvOutcome{err: fmt.Errorf("plaid %s: inconclusive HTTP %d", envURL, resp.StatusCode)}
}

// plaidEnvCheckCondition fires when the Plaid secret + client_id pair is valid
// for a specific environment (production, development, or sandbox).
type plaidEnvCheckCondition struct {
	envURL string
	client plaidHTTPClient
	cache  *plaidProbeCache
}

func (c *plaidEnvCheckCondition) markDynamic() {}

func (c *plaidEnvCheckCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	secret, ok := extractPlaidSecret(m)
	if !ok {
		return false, nil
	}
	clientID, ok := extractPlaidClientID(m)
	if !ok {
		return false, nil
	}
	out := c.cache.probe(ctx, c.httpClient(), c.envURL, clientID, secret)
	if out.err != nil {
		return false, out.err
	}
	return out.valid, nil
}

func (c *plaidEnvCheckCondition) httpClient() plaidHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// plaidRevokedCondition fires when a client_id is available and EVERY Plaid
// environment explicitly rejects the credentials with INVALID_API_KEYS.
// Transport errors, timeouts, rate limits and server errors are inconclusive --
// the condition does not fire, leaving the base score intact rather than
// marking a live key dead.
//
// Its probes share the cache with the per-environment conditions above, so on
// a finding those have already scored this costs no additional requests.
type plaidRevokedCondition struct {
	client plaidHTTPClient
	cache  *plaidProbeCache
}

func (c *plaidRevokedCondition) markDynamic() {}

func (c *plaidRevokedCondition) Evaluate(ctx context.Context, m *types.Match) (bool, error) {
	secret, ok := extractPlaidSecret(m)
	if !ok {
		return false, nil
	}
	clientID, ok := extractPlaidClientID(m)
	if !ok {
		return false, nil
	}

	for _, env := range plaidEnvironments {
		out := c.cache.probe(ctx, c.httpClient(), env, clientID, secret)
		if out.err != nil {
			return false, out.err
		}
		if !out.rejected {
			return false, nil
		}
	}
	return true, nil
}

func (c *plaidRevokedCondition) httpClient() plaidHTTPClient {
	if c.client != nil {
		return c.client
	}
	return defaultHTTPClient
}

// plaidSandboxContextCondition fires when the surrounding context or matched
// text contains "sandbox" (case-insensitive), suggesting the secret belongs to
// a sandbox environment even when no client_id is available for dynamic
// verification.
type plaidSandboxContextCondition struct{}

var sandboxLower = []byte("sandbox")

func (c *plaidSandboxContextCondition) Evaluate(_ context.Context, m *types.Match) (bool, error) {
	if m == nil {
		return false, nil
	}
	for _, seg := range [][]byte{m.Snippet.Before, m.Snippet.Matching, m.Snippet.After} {
		if bytes.Contains(bytes.ToLower(seg), sandboxLower) {
			return true, nil
		}
	}
	return false, nil
}

// PlaidGoScorer returns the environment-aware Plaid secret scorer.
//
// Targets kingfisher.plaid.2 (Production Secret, base 90) and
// kingfisher.plaid.3 (Sandbox Secret, base 40). Access tokens (plaid.4/5)
// already carry their environment in the prefix and are not scored here.
//
// Dynamic modifiers (require a co-located client_id in surrounding context)
// probe POST /institutions/get against each Plaid environment.
// Static modifiers fall back to keyword detection when no client_id is found.
//
// Product-aware scoring (auth, identity, assets) is deferred — it requires an
// access_token which is not reliably co-located with the secret.
func PlaidGoScorer() *Scorer {
	// One cache per scorer instance, shared by every modifier below, so the
	// four dynamic modifiers probe each environment once rather than six times.
	cache := newPlaidProbeCache()
	return &Scorer{
		Name:    "plaid-secret-environment",
		RuleIDs: []string{"kingfisher.plaid.2", "kingfisher.plaid.3"},
		Modifiers: []Modifier{
			// --- Static fallbacks (evaluated first, overridden by dynamic) ---

			// Context contains "sandbox" — likely a sandbox key.
			{
				Name:      "sandbox-context",
				Priority:  90,
				Kind:      ModifierKindSetScore,
				Value:     5,
				Condition: &plaidSandboxContextCondition{},
			},

			// --- Dynamic (evaluated later, override static) ---

			// Confirmed production → highest severity.
			{
				Name:     "production-verified",
				Priority: 30,
				Kind:     ModifierKindSetScore,
				Value:    95,
				Condition: &plaidEnvCheckCondition{
					envURL: plaidEnvProduction,
					cache:  cache,
				},
			},
			// Confirmed development → moderate severity (real data, limited scale).
			{
				Name:     "development-verified",
				Priority: 25,
				Kind:     ModifierKindSetScore,
				Value:    60,
				Condition: &plaidEnvCheckCondition{
					envURL: plaidEnvDevelopment,
					cache:  cache,
				},
			},
			// Confirmed sandbox → minimal severity (entirely fake data).
			{
				Name:     "sandbox-verified",
				Priority: 20,
				Kind:     ModifierKindSetScore,
				Value:    5,
				Condition: &plaidEnvCheckCondition{
					envURL: plaidEnvSandbox,
					cache:  cache,
				},
			},
			// All environments reject → revoked / dead key.
			{
				Name:      "revoked-key",
				Priority:  10,
				Kind:      ModifierKindSetScore,
				Value:     5,
				Condition: &plaidRevokedCondition{cache: cache},
			},
		},
	}
}
