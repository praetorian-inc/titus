package enum

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/titus/pkg/types"
)

const linearAPIEndpoint = "https://api.linear.app/graphql"

// LinearConfig configures the Linear workspace enumerator.
type LinearConfig struct {
	Token       string    // Linear API key (lin_api_...)
	Concurrency int       // parallel workers (default 3)
	RateLimit   float64   // requests per second (default 2)
	Verbose     io.Writer // progress output (nil = silent)
}

// LinearEnumerator enumerates blobs from a Linear workspace via the GraphQL API.
type LinearEnumerator struct {
	config   LinearConfig
	client   *http.Client
	limiter  *rate.Limiter
	endpoint string
}

// NewLinearEnumerator creates a new Linear enumerator.
func NewLinearEnumerator(cfg LinearConfig) (*LinearEnumerator, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("linear API token is required")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 3
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 2.0
	}
	return &LinearEnumerator{
		config:   cfg,
		client:   &http.Client{Timeout: 30 * time.Second},
		limiter:  rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
		endpoint: linearAPIEndpoint,
	}, nil
}

// linearProvenance builds an ExtendedProvenance for a Linear entity.
func linearProvenance(entityType, identifier, title, url, team, project string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":     "linear",
			"entityType": entityType,
			"identifier": identifier,
			"title":      title,
			"url":        url,
			"team":       team,
			"project":    project,
		},
	}
}

// logf writes a progress message when verbose output is enabled.
func (e *LinearEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
}

type graphqlRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type graphqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message    string `json:"message"`
		Extensions struct {
			Code string `json:"code"`
		} `json:"extensions"`
	} `json:"errors"`
}

// graphql sends a GraphQL query to Linear's API with rate limiting and retry.
// It retries up to 3 times on rate-limit errors (HTTP 400 with RATELIMITED code).
func (e *LinearEnumerator) graphql(ctx context.Context, query string, variables map[string]interface{}, dest interface{}) error {
	body, err := json.Marshal(graphqlRequest{Query: query, Variables: variables})
	if err != nil {
		return fmt.Errorf("marshal graphql request: %w", err)
	}

	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", e.config.Token)

		resp, err := e.client.Do(req)
		if err != nil {
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return fmt.Errorf("http request: %w", err)
		}

		var gqlResp graphqlResponse
		if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
			resp.Body.Close()
			return fmt.Errorf("decode response: %w", err)
		}
		resp.Body.Close()

		// Check for rate limit errors (Linear returns HTTP 400 with RATELIMITED code)
		rateLimited := false
		for _, gqlErr := range gqlResp.Errors {
			if gqlErr.Extensions.Code == "RATELIMITED" {
				rateLimited = true
				break
			}
		}
		if rateLimited {
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return fmt.Errorf("linear API rate limited after %d attempts", maxAttempts)
		}

		// Check for other GraphQL errors
		if len(gqlResp.Errors) > 0 {
			return fmt.Errorf("graphql error: %s", gqlResp.Errors[0].Message)
		}

		// Unmarshal data into dest
		if err := json.Unmarshal(gqlResp.Data, dest); err != nil {
			return fmt.Errorf("unmarshal data: %w", err)
		}
		return nil
	}
	return fmt.Errorf("graphql: exceeded max attempts")
}

// Enumerate discovers content from a Linear workspace and yields blobs.
func (e *LinearEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	return fmt.Errorf("not implemented")
}
