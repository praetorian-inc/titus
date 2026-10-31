package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

var coverallsRepoPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)coveralls\.io/api/v1/repos/((?:github|bitbucket|gitlab)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)`),
	regexp.MustCompile(`(?i)coveralls\.io/repos/((?:github|bitbucket|gitlab)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)`),
	regexp.MustCompile(`(?i)coveralls\.io/((?:github|bitbucket|gitlab)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)`),
}

type CoverallsValidator struct {
	client  *http.Client
	baseURL string
}

func NewCoverallsValidator() *CoverallsValidator {
	return &CoverallsValidator{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: "https://coveralls.io",
	}
}

func NewCoverallsValidatorWithClient(client *http.Client, baseURL string) *CoverallsValidator {
	return &CoverallsValidator{client: client, baseURL: baseURL}
}

func (v *CoverallsValidator) Name() string { return "coveralls" }

func (v *CoverallsValidator) CanValidate(ruleID string) bool {
	return ruleID == "kingfisher.coveralls.2"
}

func (v *CoverallsValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	token := extractNamedGroup(match, "token")
	if token == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "no token found in match"), nil
	}

	repoPath := extractCoverallsRepo(match.Snippet)
	if repoPath == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0, "coveralls repo path not found in context"), nil
	}

	url := fmt.Sprintf("%s/api/v1/repos/%s", v.baseURL, repoPath)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return types.NewValidationResult(types.StatusValid, 1.0, fmt.Sprintf("valid Coveralls token for %s", repoPath)), nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("invalid Coveralls token: HTTP %d", resp.StatusCode)), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("unexpected status: HTTP %d", resp.StatusCode)), nil
	}
}

func extractCoverallsRepo(snippet types.Snippet) string {
	parts := [][]byte{snippet.Before, snippet.Matching, snippet.After}
	for _, pattern := range coverallsRepoPatterns {
		for _, part := range parts {
			if m := pattern.FindSubmatch(part); len(m) >= 2 {
				return string(m[1])
			}
		}
	}
	return ""
}
