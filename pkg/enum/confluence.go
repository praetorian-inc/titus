package enum

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/titus/pkg/types"
)

// ConfluenceConfig configures the Confluence instance enumerator.
type ConfluenceConfig struct {
	BaseURL          string    // Confluence base URL (e.g., https://mysite.atlassian.net/wiki)
	Token            string    // API token or PAT
	Username         string    // Username for Cloud basic auth (empty = PAT/Bearer)
	RateLimit        float64   // requests per second (default 5)
	Spaces           string    // comma-separated space key filter (empty = all)
	AllowInsecureHTTP bool     // allow plaintext HTTP base URLs
	Verbose          io.Writer // progress output (nil = silent)
}

// ConfluenceEnumerator enumerates blobs from a Confluence instance via the REST API.
type ConfluenceEnumerator struct {
	config  ConfluenceConfig
	client  *http.Client
	limiter *rate.Limiter
	apiBase string
}

// NewConfluenceEnumerator creates a new Confluence enumerator.
func NewConfluenceEnumerator(cfg ConfluenceConfig) (*ConfluenceEnumerator, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("confluence API token is required")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("confluence base URL is required")
	}
	insecure, err := ValidateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("confluence base URL: %w", err)
	}
	if insecure && !cfg.AllowInsecureHTTP {
		return nil, fmt.Errorf("confluence base URL uses plaintext HTTP, which exposes credentials; use HTTPS or set AllowInsecureHTTP")
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 5.0
	}

	apiBase := strings.TrimRight(cfg.BaseURL, "/") + "/rest/api"

	return &ConfluenceEnumerator{
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
		apiBase: apiBase,
	}, nil
}

// confluenceProvenance builds an ExtendedProvenance for a Confluence entity.
func confluenceProvenance(entityType, id, title, url, space string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":     "confluence",
			"entityType": entityType,
			"identifier": id,
			"title":      title,
			"url":        url,
			"path":       url,
			"space":      space,
		},
	}
}

// logf writes a progress message when verbose output is enabled.
func (e *ConfluenceEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
}

// progressf writes an in-place progress update using \r.
func (e *ConfluenceEnumerator) progressf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s", fmt.Sprintf(format, args...))
	}
}

var (
	cfCDATARe  = regexp.MustCompile(`(?s)<!\[CDATA\[(.*?)\]\]>`)
	cfHTMLTagRe = regexp.MustCompile(`<[^>]*>`)
)

// cfStripHTML removes HTML tags and unescapes HTML entities, preserving CDATA content.
func cfStripHTML(s string) string {
	// Extract CDATA content before stripping HTML tags.
	s = cfCDATARe.ReplaceAllString(s, "$1")
	stripped := cfHTMLTagRe.ReplaceAllString(s, "")
	return html.UnescapeString(stripped)
}

// cfComment holds author and body of a Confluence comment.
type cfComment struct {
	Author string
	Body   string
}

// cfBuildPageBlob assembles a Confluence page/blogpost into a single blob.
func cfBuildPageBlob(title, url, space, contentType, body string, comments []cfComment) []byte {
	var sb strings.Builder
	sb.WriteString("Title: " + title + "\n")
	sb.WriteString("URL: " + url + "\n")
	sb.WriteString("Space: " + space + "\n")
	sb.WriteString("Type: " + contentType + "\n")
	sb.WriteString("---\n")
	sb.WriteString(body + "\n")
	if len(comments) > 0 {
		sb.WriteString("\n--- Comments ---\n")
		for _, c := range comments {
			sb.WriteString("\n[" + c.Author + "]:\n")
			sb.WriteString(c.Body + "\n")
		}
	}
	return []byte(sb.String())
}

// cfPaginatedResponse holds common pagination fields from the Confluence REST API.
type cfPaginatedResponse struct {
	Results json.RawMessage `json:"results"`
	Start   int             `json:"start"`
	Limit   int             `json:"limit"`
	Size    int             `json:"size"`
	Links   struct {
		Next string `json:"next"`
	} `json:"_links"`
}

// cfSpace represents a Confluence space.
type cfSpace struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// cfContent represents a Confluence page or blogpost.
type cfContent struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Type  string `json:"type"`
	Body  struct {
		Storage struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	Links struct {
		WebUI string `json:"webui"`
	} `json:"_links"`
}

// cfGet performs a rate-limited GET request with auth and retry logic.
func (e *ConfluenceEnumerator) cfGet(ctx context.Context, url string) ([]byte, error) {
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}

		// Auth: Basic (username:token) or Bearer (PAT)
		if e.config.Username != "" {
			encoded := base64.StdEncoding.EncodeToString([]byte(e.config.Username + ":" + e.config.Token))
			req.Header.Set("Authorization", "Basic "+encoded)
		} else {
			req.Header.Set("Authorization", "Bearer "+e.config.Token)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := e.client.Do(req)
		if err != nil {
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return nil, fmt.Errorf("http request: %w", err)
		}

		// Retry on 429 (rate limit) or 5xx (server error)
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return nil, fmt.Errorf("confluence API returned %d after %d attempts", resp.StatusCode, maxAttempts)
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("confluence API returned unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
		return body, nil
	}
	return nil, fmt.Errorf("cfGet: exceeded max attempts")
}

// cfFetchSpaces retrieves all spaces, optionally filtered by the Spaces config.
func (e *ConfluenceEnumerator) cfFetchSpaces(ctx context.Context) ([]cfSpace, error) {
	var allowed map[string]bool
	if e.config.Spaces != "" {
		allowed = make(map[string]bool)
		for _, k := range strings.Split(e.config.Spaces, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				allowed[k] = true
			}
		}
	}

	var allSpaces []cfSpace
	start := 0
	limit := 25
	for {
		url := fmt.Sprintf("%s/space?limit=%d&start=%d", e.apiBase, limit, start)
		body, err := e.cfGet(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch spaces: %w", err)
		}

		var page cfPaginatedResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode spaces response: %w", err)
		}

		var spaces []cfSpace
		if err := json.Unmarshal(page.Results, &spaces); err != nil {
			return nil, fmt.Errorf("decode spaces results: %w", err)
		}

		for _, s := range spaces {
			if allowed == nil || allowed[s.Key] {
				allSpaces = append(allSpaces, s)
			}
		}

		if page.Size == 0 || page.Links.Next == "" {
			break
		}
		start += page.Size
	}
	return allSpaces, nil
}

// cfFetchContent retrieves all content of a given type (page or blogpost) in a space.
func (e *ConfluenceEnumerator) cfFetchContent(ctx context.Context, spaceKey, contentType string) ([]cfContent, error) {
	var allContent []cfContent
	start := 0
	limit := 25
	for {
		url := fmt.Sprintf("%s/content?spaceKey=%s&type=%s&limit=%d&start=%d&expand=body.storage,version",
			e.apiBase, spaceKey, contentType, limit, start)
		body, err := e.cfGet(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch %s content in space %s: %w", contentType, spaceKey, err)
		}

		var page cfPaginatedResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode content response: %w", err)
		}

		var items []cfContent
		if err := json.Unmarshal(page.Results, &items); err != nil {
			return nil, fmt.Errorf("decode content results: %w", err)
		}
		allContent = append(allContent, items...)

		if page.Size == 0 || page.Links.Next == "" {
			break
		}
		start += page.Size
	}
	return allContent, nil
}

// cfFetchComments retrieves all comments on a page/blogpost.
func (e *ConfluenceEnumerator) cfFetchComments(ctx context.Context, contentID string) ([]cfComment, error) {
	var allComments []cfComment
	start := 0
	limit := 25
	for {
		url := fmt.Sprintf("%s/content/%s/child/comment?limit=%d&start=%d&expand=body.storage",
			e.apiBase, contentID, limit, start)
		body, err := e.cfGet(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch comments for content %s: %w", contentID, err)
		}

		var page cfPaginatedResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode comments response: %w", err)
		}

		var items []cfContent
		if err := json.Unmarshal(page.Results, &items); err != nil {
			return nil, fmt.Errorf("decode comment results: %w", err)
		}

		for _, item := range items {
			allComments = append(allComments, cfComment{
				Author: item.Title,
				Body:   cfStripHTML(item.Body.Storage.Value),
			})
		}

		if page.Size == 0 || page.Links.Next == "" {
			break
		}
		start += page.Size
	}
	return allComments, nil
}

// Enumerate discovers content from a Confluence instance and yields blobs.
func (e *ConfluenceEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	spaces, err := e.cfFetchSpaces(ctx)
	if err != nil {
		return err
	}
	e.logf("Found %d spaces, scanning for secrets...", len(spaces))

	var count atomic.Int64
	var errs []string

	for _, space := range spaces {
		// Fetch pages
		var allContent []cfContent
		pages, err := e.cfFetchContent(ctx, space.Key, "page")
		if err != nil {
			errs = append(errs, fmt.Sprintf("space %s pages: %v", space.Key, err))
		} else {
			allContent = append(allContent, pages...)
		}

		// Fetch blog posts
		blogs, err := e.cfFetchContent(ctx, space.Key, "blogpost")
		if err != nil {
			errs = append(errs, fmt.Sprintf("space %s blogposts: %v", space.Key, err))
		} else {
			allContent = append(allContent, blogs...)
		}

		for _, item := range allContent {
			comments, err := e.cfFetchComments(ctx, item.ID)
			if err != nil {
				errs = append(errs, fmt.Sprintf("comments for %s: %v", item.ID, err))
				// Continue to emit the page body even without comments.
			}

			strippedBody := cfStripHTML(item.Body.Storage.Value)

			pageURL := strings.TrimRight(e.config.BaseURL, "/") + item.Links.WebUI
			blob := cfBuildPageBlob(item.Title, pageURL, space.Key, item.Type, strippedBody, comments)
			blobID := types.ComputeBlobID(blob)
			prov := confluenceProvenance(item.Type, item.ID, item.Title, pageURL, space.Key)

			n := count.Add(1)
			e.progressf("Scanning content: %d items", n)

			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}
	}

	e.logf("Scanned %d content items across %d spaces", count.Load(), len(spaces))

	if len(errs) > 0 {
		return fmt.Errorf("enumeration errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
