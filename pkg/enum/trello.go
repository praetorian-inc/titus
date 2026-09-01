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

const trelloAPIBase = "https://api.trello.com/1"

// TrelloConfig configures the Trello enumerator.
type TrelloConfig struct {
	APIKey    string    // Trello Power-Up API key
	Token     string    // Trello user token
	Boards    []string  // board IDs to scan (empty = all)
	RateLimit float64   // requests per second (default 3)
	Verbose   io.Writer // progress output (nil = silent)
}

// TrelloEnumerator enumerates blobs from Trello boards via the REST API.
type TrelloEnumerator struct {
	config  TrelloConfig
	client  *http.Client
	limiter *rate.Limiter
	apiBase string
}

// NewTrelloEnumerator creates a new Trello enumerator.
func NewTrelloEnumerator(cfg TrelloConfig) (*TrelloEnumerator, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("trello API key is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("trello token is required")
	}

	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 3.0
	}

	return &TrelloEnumerator{
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
		apiBase: trelloAPIBase,
	}, nil
}

func trelloProvenance(entityType, id, title, recordURL string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":     "trello",
			"entityType": entityType,
			"identifier": id,
			"title":      title,
			"url":        recordURL,
			"path":       recordURL,
		},
	}
}

func (e *TrelloEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
}

func (e *TrelloEnumerator) progressf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s", fmt.Sprintf(format, args...))
	}
}

// trelloGet performs a rate-limited GET with Trello auth and retry.
func (e *TrelloEnumerator) trelloGet(ctx context.Context, path string) ([]byte, error) {
	const maxAttempts = 3

	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	reqURL := fmt.Sprintf("%s%s%skey=%s&token=%s", e.apiBase, path, sep, e.config.APIKey, e.config.Token)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
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
			return nil, fmt.Errorf("trello API returned %d after %d attempts", resp.StatusCode, maxAttempts)
		}

		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("trello API returned unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
		return body, nil
	}
	return nil, fmt.Errorf("trelloGet: exceeded max attempts")
}

type trelloBoard struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
	URL  string `json:"url"`
}

type trelloCard struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
	URL  string `json:"url"`
}

type trelloAction struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data struct {
		Text string `json:"text"`
	} `json:"data"`
}

type trelloChecklist struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	CheckItems []trelloCheckItem   `json:"checkItems"`
}

type trelloCheckItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (e *TrelloEnumerator) trelloFetchBoards(ctx context.Context) ([]trelloBoard, error) {
	body, err := e.trelloGet(ctx, "/members/me/boards?fields=id,name,desc,url")
	if err != nil {
		return nil, fmt.Errorf("fetch boards: %w", err)
	}

	var boards []trelloBoard
	if err := json.Unmarshal(body, &boards); err != nil {
		return nil, fmt.Errorf("decode boards: %w", err)
	}
	return boards, nil
}

func (e *TrelloEnumerator) trelloFetchCards(ctx context.Context, boardID string) ([]trelloCard, error) {
	path := fmt.Sprintf("/boards/%s/cards?fields=id,name,desc,url&filter=all", boardID)
	body, err := e.trelloGet(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("fetch cards for board %s: %w", boardID, err)
	}

	var cards []trelloCard
	if err := json.Unmarshal(body, &cards); err != nil {
		return nil, fmt.Errorf("decode cards for board %s: %w", boardID, err)
	}
	return cards, nil
}

func (e *TrelloEnumerator) trelloFetchComments(ctx context.Context, cardID string) ([]trelloAction, error) {
	path := fmt.Sprintf("/cards/%s/actions?filter=commentCard&limit=1000", cardID)
	body, err := e.trelloGet(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("fetch comments for card %s: %w", cardID, err)
	}

	var actions []trelloAction
	if err := json.Unmarshal(body, &actions); err != nil {
		return nil, fmt.Errorf("decode comments for card %s: %w", cardID, err)
	}
	return actions, nil
}

func (e *TrelloEnumerator) trelloFetchChecklists(ctx context.Context, cardID string) ([]trelloChecklist, error) {
	path := fmt.Sprintf("/cards/%s/checklists", cardID)
	body, err := e.trelloGet(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("fetch checklists for card %s: %w", cardID, err)
	}

	var checklists []trelloChecklist
	if err := json.Unmarshal(body, &checklists); err != nil {
		return nil, fmt.Errorf("decode checklists for card %s: %w", cardID, err)
	}
	return checklists, nil
}

func trelloBuildCardBlob(boardName string, card trelloCard, comments []trelloAction, checklists []trelloChecklist) []byte {
	var sb strings.Builder
	sb.WriteString("Board: " + boardName + "\n")
	sb.WriteString("Card: " + card.Name + "\n")
	if card.URL != "" {
		sb.WriteString("URL: " + card.URL + "\n")
	}
	sb.WriteString("---\n")

	if card.Desc != "" {
		sb.WriteString(card.Desc + "\n")
	}

	for _, cl := range checklists {
		fmt.Fprintf(&sb, "\n--- Checklist: %s ---\n", cl.Name)
		for _, item := range cl.CheckItems {
			sb.WriteString("- " + item.Name + "\n")
		}
	}

	for _, c := range comments {
		if c.Data.Text != "" {
			sb.WriteString("\n--- Comment ---\n")
			sb.WriteString(c.Data.Text + "\n")
		}
	}
	return []byte(sb.String())
}

// Enumerate discovers content from Trello boards and yields blobs.
func (e *TrelloEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	e.logf("Scanning Trello boards")

	var count atomic.Int64
	var errs []string

	boards, err := e.trelloFetchBoards(ctx)
	if err != nil {
		return fmt.Errorf("fetching boards: %w", err)
	}

	// Filter boards if specific ones requested.
	if len(e.config.Boards) > 0 {
		boardSet := make(map[string]bool, len(e.config.Boards))
		for _, b := range e.config.Boards {
			boardSet[b] = true
		}
		var filtered []trelloBoard
		for _, b := range boards {
			if boardSet[b.ID] {
				filtered = append(filtered, b)
			}
		}
		boards = filtered
	}

	e.logf("Found %d boards", len(boards))

	for _, board := range boards {
		cards, err := e.trelloFetchCards(ctx, board.ID)
		if err != nil {
			errs = append(errs, fmt.Sprintf("board %s: %v", board.ID, err))
			continue
		}

		e.logf("Board %q: %d cards", board.Name, len(cards))

		for _, card := range cards {
			comments, err := e.trelloFetchComments(ctx, card.ID)
			if err != nil {
				errs = append(errs, fmt.Sprintf("card %s comments: %v", card.ID, err))
				comments = nil
			}

			checklists, err := e.trelloFetchChecklists(ctx, card.ID)
			if err != nil {
				errs = append(errs, fmt.Sprintf("card %s checklists: %v", card.ID, err))
				checklists = nil
			}

			blob := trelloBuildCardBlob(board.Name, card, comments, checklists)
			blobID := types.ComputeBlobID(blob)
			prov := trelloProvenance("card", card.ID, card.Name, card.URL)

			n := count.Add(1)
			e.progressf("Scanning cards: %d", n)

			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}
	}

	e.logf("Scanned %d cards across %d boards", count.Load(), len(boards))

	if len(errs) > 0 {
		return fmt.Errorf("enumeration errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
