package enum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/titus/pkg/types"
)

// ZendeskConfig configures the Zendesk enumerator.
type ZendeskConfig struct {
	Subdomain string    // Zendesk subdomain (e.g., "mycompany" for mycompany.zendesk.com)
	Email     string    // agent email address
	Token     string    // API token
	RateLimit float64   // requests per second (default 3)
	Verbose   io.Writer // progress output (nil = silent)
}

// ZendeskEnumerator enumerates blobs from a Zendesk instance via the REST API v2.
type ZendeskEnumerator struct {
	config  ZendeskConfig
	client  *http.Client
	limiter *rate.Limiter
	apiBase string
}

// NewZendeskEnumerator creates a new Zendesk enumerator.
func NewZendeskEnumerator(cfg ZendeskConfig) (*ZendeskEnumerator, error) {
	if cfg.Subdomain == "" {
		return nil, fmt.Errorf("zendesk subdomain is required")
	}
	if cfg.Email == "" {
		return nil, fmt.Errorf("zendesk email is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("zendesk API token is required")
	}

	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 3.0
	}

	apiBase := fmt.Sprintf("https://%s.zendesk.com", cfg.Subdomain)

	return &ZendeskEnumerator{
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
		apiBase: apiBase,
	}, nil
}

func zdProvenance(entityType, id, title, recordURL string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":     "zendesk",
			"entityType": entityType,
			"identifier": id,
			"title":      title,
			"url":        recordURL,
			"path":       recordURL,
		},
	}
}

func (e *ZendeskEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
}

func (e *ZendeskEnumerator) progressf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s", fmt.Sprintf(format, args...))
	}
}

// zdGet performs a rate-limited GET with Zendesk auth and retry.
func (e *ZendeskEnumerator) zdGet(ctx context.Context, reqURL string) ([]byte, error) {
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}

		req.SetBasicAuth(e.config.Email+"/token", e.config.Token)
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

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			_ = resp.Body.Close()
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return nil, fmt.Errorf("zendesk API returned %d after %d attempts", resp.StatusCode, maxAttempts)
		}

		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("zendesk API returned unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
		return body, nil
	}
	return nil, fmt.Errorf("zdGet: exceeded max attempts")
}

type zdTicketsResponse struct {
	Tickets []zdTicket `json:"tickets"`
	NextPage string    `json:"next_page"`
}

type zdTicket struct {
	ID          int64  `json:"id"`
	Subject     string `json:"subject"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

type zdCommentsResponse struct {
	Comments []zdComment `json:"comments"`
	NextPage string      `json:"next_page"`
}

type zdComment struct {
	ID        int64  `json:"id"`
	Body      string `json:"body"`
	PlainBody string `json:"plain_body"`
	Public    bool   `json:"public"`
}

type zdArticlesResponse struct {
	Articles []zdArticle `json:"articles"`
	NextPage string      `json:"next_page"`
}

type zdArticle struct {
	ID    int64  `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
	URL   string `json:"html_url"`
}

func (e *ZendeskEnumerator) zdFetchTickets(ctx context.Context) ([]zdTicket, error) {
	var all []zdTicket
	url := e.apiBase + "/api/v2/tickets.json?page[size]=100"

	for url != "" {
		body, err := e.zdGet(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch tickets: %w", err)
		}

		var resp zdTicketsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode tickets: %w", err)
		}

		all = append(all, resp.Tickets...)
		url = resp.NextPage
	}
	return all, nil
}

func (e *ZendeskEnumerator) zdFetchComments(ctx context.Context, ticketID int64) ([]zdComment, error) {
	var all []zdComment
	url := fmt.Sprintf("%s/api/v2/tickets/%d/comments.json", e.apiBase, ticketID)

	for url != "" {
		body, err := e.zdGet(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch comments for ticket %d: %w", ticketID, err)
		}

		var resp zdCommentsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode comments for ticket %d: %w", ticketID, err)
		}

		all = append(all, resp.Comments...)
		url = resp.NextPage
	}
	return all, nil
}

func (e *ZendeskEnumerator) zdFetchArticles(ctx context.Context) ([]zdArticle, error) {
	var all []zdArticle
	url := e.apiBase + "/api/v2/help_center/articles.json?page[size]=100"

	for url != "" {
		body, err := e.zdGet(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetch articles: %w", err)
		}

		var resp zdArticlesResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode articles: %w", err)
		}

		all = append(all, resp.Articles...)
		url = resp.NextPage
	}
	return all, nil
}

func zdBuildTicketBlob(ticket zdTicket, comments []zdComment, subdomain string) []byte {
	var sb strings.Builder
	sb.WriteString("Type: ticket\n")
	sb.WriteString(fmt.Sprintf("ID: %d\n", ticket.ID))
	if ticket.Subject != "" {
		sb.WriteString("Subject: " + ticket.Subject + "\n")
	}
	ticketURL := fmt.Sprintf("https://%s.zendesk.com/agent/tickets/%d", subdomain, ticket.ID)
	sb.WriteString("URL: " + ticketURL + "\n")
	sb.WriteString("---\n")

	if ticket.Description != "" {
		sb.WriteString(ticket.Description + "\n")
	}

	for _, c := range comments {
		body := c.PlainBody
		if body == "" {
			body = c.Body
		}
		if body == "" {
			continue
		}
		visibility := "public"
		if !c.Public {
			visibility = "internal"
		}
		sb.WriteString(fmt.Sprintf("\n--- Comment (%s) ---\n", visibility))
		sb.WriteString(body + "\n")
	}
	return []byte(sb.String())
}

func zdBuildArticleBlob(article zdArticle) []byte {
	var sb strings.Builder
	sb.WriteString("Type: article\n")
	sb.WriteString(fmt.Sprintf("ID: %d\n", article.ID))
	if article.Title != "" {
		sb.WriteString("Title: " + article.Title + "\n")
	}
	if article.URL != "" {
		sb.WriteString("URL: " + article.URL + "\n")
	}
	sb.WriteString("---\n")

	if article.Body != "" {
		sb.WriteString(article.Body + "\n")
	}
	return []byte(sb.String())
}

// Enumerate discovers content from a Zendesk instance and yields blobs.
func (e *ZendeskEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	e.logf("Scanning Zendesk instance: %s.zendesk.com", e.config.Subdomain)

	var count atomic.Int64
	var errs []string

	// Fetch and yield tickets with their comments.
	tickets, err := e.zdFetchTickets(ctx)
	if err != nil {
		errs = append(errs, fmt.Sprintf("tickets: %v", err))
	} else {
		e.logf("Found %d tickets", len(tickets))

		for _, ticket := range tickets {
			comments, err := e.zdFetchComments(ctx, ticket.ID)
			if err != nil {
				errs = append(errs, fmt.Sprintf("ticket %d comments: %v", ticket.ID, err))
				comments = nil
			}

			blob := zdBuildTicketBlob(ticket, comments, e.config.Subdomain)
			blobID := types.ComputeBlobID(blob)
			ticketURL := fmt.Sprintf("https://%s.zendesk.com/agent/tickets/%d", e.config.Subdomain, ticket.ID)
			prov := zdProvenance("ticket", fmt.Sprintf("%d", ticket.ID), ticket.Subject, ticketURL)

			n := count.Add(1)
			e.progressf("Scanning: %d items", n)

			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}
	}

	// Fetch and yield help center articles.
	articles, err := e.zdFetchArticles(ctx)
	if err != nil {
		errs = append(errs, fmt.Sprintf("articles: %v", err))
	} else {
		e.logf("Found %d articles", len(articles))

		for _, article := range articles {
			blob := zdBuildArticleBlob(article)
			blobID := types.ComputeBlobID(blob)
			prov := zdProvenance("article", fmt.Sprintf("%d", article.ID), article.Title, article.URL)

			n := count.Add(1)
			e.progressf("Scanning: %d items", n)

			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}
	}

	e.logf("Scanned %d items from Zendesk", count.Load())

	if len(errs) > 0 {
		return fmt.Errorf("enumeration errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
