package validator

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

type SentryDSNValidator struct {
	client  *http.Client
	timeout time.Duration
}

func NewSentryDSNValidator() *SentryDSNValidator {
	return &SentryDSNValidator{
		timeout: 5 * time.Second,
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (v *SentryDSNValidator) Name() string { return "sentry-dsn" }

func (v *SentryDSNValidator) CanValidate(ruleID string) bool {
	return ruleID == "kingfisher.sentry.4"
}

func (v *SentryDSNValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	dsn, err := v.parseDSN(match)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("cannot validate: %v", err)), nil
	}

	if isLocalhost(dsn.host) {
		return types.NewValidationResult(types.StatusUndetermined, 0, "skipping localhost address — cannot validate"), nil
	}

	envelopeURL := fmt.Sprintf("https://%s/api/%s/envelope/", dsn.hostPort, dsn.projectID)

	body := fmt.Sprintf("{\"sent_at\":\"2024-01-01T00:00:00Z\",\"dsn\":\"%s\"}\n", dsn.raw)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, envelopeURL, strings.NewReader(body))
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}

	req.Header.Set("Content-Type", "application/x-sentry-envelope")
	req.Header.Set("X-Sentry-Auth", fmt.Sprintf("Sentry sentry_version=7, sentry_key=%s, sentry_client=titus/1.0", dsn.key))

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == 200 || resp.StatusCode == 202:
		return types.NewValidationResult(types.StatusValid, 1.0, "Sentry DSN is valid"), nil
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return types.NewValidationResult(types.StatusInvalid, 1.0, "Sentry DSN rejected — invalid key or project"), nil
	case resp.StatusCode == 429:
		return types.NewValidationResult(types.StatusUndetermined, 0.7, "Sentry rate limited — DSN may be valid"), nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("redirect to %s — cannot confirm DSN validity", resp.Header.Get("Location"))), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("unexpected status %d", resp.StatusCode)), nil
	}
}

type sentryDSN struct {
	raw       string
	key       string
	host      string
	hostPort  string
	projectID string
}

func (v *SentryDSNValidator) parseDSN(match *types.Match) (*sentryDSN, error) {
	if len(match.Groups) == 0 {
		return nil, fmt.Errorf("no DSN found in match")
	}

	raw := string(match.Groups[0])
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid DSN: %w", err)
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("unexpected scheme %q", u.Scheme)
	}

	key := u.User.Username()
	if key == "" {
		return nil, fmt.Errorf("no key in DSN")
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("no host in DSN")
	}

	projectID := strings.TrimPrefix(u.Path, "/")
	if projectID == "" {
		return nil, fmt.Errorf("no project ID in DSN")
	}

	return &sentryDSN{
		raw:       raw,
		key:       key,
		host:      host,
		hostPort:  u.Host,
		projectID: projectID,
	}, nil
}
