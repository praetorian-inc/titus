package enum

import (
	"context"
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

// Enumerate discovers content from a Linear workspace and yields blobs.
func (e *LinearEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	return fmt.Errorf("not implemented")
}
