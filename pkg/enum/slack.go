package enum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/titus/pkg/types"
)

const slackAPIBase = "https://slack.com/api/"

// SlackConfig configures the Slack workspace enumerator.
type SlackConfig struct {
	Token     string    // Slack Bot or User token (xoxb-... or xoxp-...)
	RateLimit float64   // requests per second (default 1.0)
	Channels  string    // comma-separated channel name filter (empty = all)
	Verbose   io.Writer // progress output (nil = silent)
}

// SlackEnumerator enumerates blobs from a Slack workspace via the Web API.
type SlackEnumerator struct {
	config  SlackConfig
	client  *http.Client
	limiter *rate.Limiter
	baseURL string
}

// NewSlackEnumerator creates a new Slack enumerator.
func NewSlackEnumerator(cfg SlackConfig) (*SlackEnumerator, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("slack API token is required")
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 1.0
	}
	return &SlackEnumerator{
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
		baseURL: slackAPIBase,
	}, nil
}

// slackProvenance builds an ExtendedProvenance for a Slack channel.
func slackProvenance(channel, channelID, url, path string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":    "slack",
			"channel":   channel,
			"channelID": channelID,
			"url":       url,
			"path":      path,
		},
	}
}

// logf writes a progress message when verbose output is enabled.
func (e *SlackEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
}

// progressf writes an in-place progress update using \r.
func (e *SlackEnumerator) progressf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s", fmt.Sprintf(format, args...))
	}
}

// slConversation represents a Slack channel/conversation.
type slConversation struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IsChannel  bool   `json:"is_channel"`
	IsGroup    bool   `json:"is_group"`
	IsIM       bool   `json:"is_im"`
	IsMPIM     bool   `json:"is_mpim"`
	IsPrivate  bool   `json:"is_private"`
	IsArchived bool   `json:"is_archived"`
}

// slMessage represents a Slack message.
type slMessage struct {
	Type       string `json:"type"`
	User       string `json:"user"`
	Text       string `json:"text"`
	TS         string `json:"ts"`
	ReplyCount int    `json:"reply_count"`
}

// slConversationsListResponse maps conversations.list API response.
type slConversationsListResponse struct {
	OK               bool             `json:"ok"`
	Error            string           `json:"error,omitempty"`
	Channels         []slConversation `json:"channels"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// slConversationsHistoryResponse maps conversations.history API response.
type slConversationsHistoryResponse struct {
	OK               bool        `json:"ok"`
	Error            string      `json:"error,omitempty"`
	Messages         []slMessage `json:"messages"`
	HasMore          bool        `json:"has_more"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// slConversationsRepliesResponse maps conversations.replies API response.
type slConversationsRepliesResponse struct {
	OK               bool        `json:"ok"`
	Error            string      `json:"error,omitempty"`
	Messages         []slMessage `json:"messages"`
	HasMore          bool        `json:"has_more"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// slGet sends a GET request to the Slack Web API with rate limiting and retry.
// Retries up to 3 times on 429 or 5xx responses.
func (e *SlackEnumerator) slGet(ctx context.Context, endpoint string) ([]byte, error) {
	const maxAttempts = 3

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.baseURL+endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+e.config.Token)

		resp, err := e.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt < maxAttempts-1 {
				continue // network error, retry
			}
			return nil, fmt.Errorf("http request: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			if attempt < maxAttempts-1 {
				continue
			}
			return nil, fmt.Errorf("read response body: %w", err)
		}

		if resp.StatusCode == 429 {
			backoff := 3 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
					backoff = time.Duration(secs) * time.Second
				}
			}
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(backoff):
				}
				continue
			}
			return nil, fmt.Errorf("slack API %s rate limited after %d attempts", endpoint, maxAttempts)
		}

		if resp.StatusCode >= 500 {
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return nil, fmt.Errorf("slack API %s returned %d after %d attempts", endpoint, resp.StatusCode, maxAttempts)
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("slack API %s returned unexpected status %d", endpoint, resp.StatusCode)
		}

		return body, nil
	}

	return nil, fmt.Errorf("slack API %s failed after %d attempts", endpoint, maxAttempts)
}

// slListConversations paginates through all conversations in the workspace.
func (e *SlackEnumerator) slListConversations(ctx context.Context) ([]slConversation, error) {
	var all []slConversation
	cursor := ""

	for {
		endpoint := "conversations.list?types=public_channel,private_channel,mpim,im&limit=200"
		if cursor != "" {
			endpoint += "&cursor=" + cursor
		}

		body, err := e.slGet(ctx, endpoint)
		if err != nil {
			return nil, fmt.Errorf("list conversations: %w", err)
		}

		var resp slConversationsListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode conversations.list: %w", err)
		}
		if !resp.OK {
			return nil, fmt.Errorf("conversations.list error: %s", resp.Error)
		}

		all = append(all, resp.Channels...)

		nextCursor := resp.ResponseMetadata.NextCursor
		if nextCursor == "" || nextCursor == cursor {
			break
		}
		cursor = nextCursor
	}

	return all, nil
}

// slFetchHistory paginates through all messages in a channel.
func (e *SlackEnumerator) slFetchHistory(ctx context.Context, channelID string) ([]slMessage, error) {
	var all []slMessage
	cursor := ""

	for {
		endpoint := "conversations.history?channel=" + channelID + "&limit=200"
		if cursor != "" {
			endpoint += "&cursor=" + cursor
		}

		body, err := e.slGet(ctx, endpoint)
		if err != nil {
			return nil, fmt.Errorf("fetch history for %s: %w", channelID, err)
		}

		var resp slConversationsHistoryResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode conversations.history: %w", err)
		}
		if !resp.OK {
			return nil, fmt.Errorf("conversations.history error: %s", resp.Error)
		}

		all = append(all, resp.Messages...)

		nextCursor := resp.ResponseMetadata.NextCursor
		if !resp.HasMore || nextCursor == "" || nextCursor == cursor {
			break
		}
		cursor = nextCursor
	}

	return all, nil
}

// slFetchReplies fetches all replies in a message thread.
func (e *SlackEnumerator) slFetchReplies(ctx context.Context, channelID, threadTS string) ([]slMessage, error) {
	var all []slMessage
	cursor := ""

	for {
		endpoint := "conversations.replies?channel=" + channelID + "&ts=" + threadTS + "&limit=200"
		if cursor != "" {
			endpoint += "&cursor=" + cursor
		}

		body, err := e.slGet(ctx, endpoint)
		if err != nil {
			return nil, fmt.Errorf("fetch replies for %s/%s: %w", channelID, threadTS, err)
		}

		var resp slConversationsRepliesResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode conversations.replies: %w", err)
		}
		if !resp.OK {
			return nil, fmt.Errorf("conversations.replies error: %s", resp.Error)
		}

		all = append(all, resp.Messages...)

		nextCursor := resp.ResponseMetadata.NextCursor
		if !resp.HasMore || nextCursor == "" || nextCursor == cursor {
			break
		}
		cursor = nextCursor
	}

	return all, nil
}

// slBuildChannelBlob assembles all messages from a channel into a single blob.
func slBuildChannelBlob(channelName, channelURL, channelID string, messages []slMessage) []byte {
	var sb strings.Builder
	sb.WriteString("Channel: " + channelName + "\n")
	sb.WriteString("URL: " + channelURL + "\n")
	sb.WriteString("ID: " + channelID + "\n")
	sb.WriteString("---\n")
	for _, msg := range messages {
		sb.WriteString("[" + msg.User + "] [" + msg.TS + "]: " + msg.Text + "\n")
	}
	return []byte(sb.String())
}

// slChannelURL returns the Slack web URL for a channel.
func slChannelURL(channelID string) string {
	return "https://app.slack.com/client/" + channelID
}

// slFilterChannels filters conversations by the --channels flag.
func slFilterChannels(conversations []slConversation, filter string) []slConversation {
	if filter == "" {
		return conversations
	}
	allowed := make(map[string]bool)
	for _, name := range strings.Split(filter, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			allowed[name] = true
		}
	}
	var filtered []slConversation
	for _, c := range conversations {
		if allowed[c.Name] {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// Enumerate discovers content from a Slack workspace and yields blobs.
func (e *SlackEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	e.logf("Listing conversations...")

	conversations, err := e.slListConversations(ctx)
	if err != nil {
		return fmt.Errorf("listing conversations: %w", err)
	}

	conversations = slFilterChannels(conversations, e.config.Channels)

	total := len(conversations)
	e.logf("Found %d conversations, scanning for secrets...", total)

	var channelCount atomic.Int64

	for _, conv := range conversations {
		channelName := conv.Name
		if channelName == "" {
			channelName = conv.ID
		}
		channelURL := slChannelURL(conv.ID)

		// Fetch channel history
		messages, err := e.slFetchHistory(ctx, conv.ID)
		if err != nil {
			return fmt.Errorf("fetching history for %s: %w", channelName, err)
		}

		// For messages with threads, fetch replies
		var allMessages []slMessage
		for _, msg := range messages {
			allMessages = append(allMessages, msg)
			if msg.ReplyCount > 0 {
				replies, err := e.slFetchReplies(ctx, conv.ID, msg.TS)
				if err != nil {
					return fmt.Errorf("fetching replies for %s/%s: %w", channelName, msg.TS, err)
				}
				// Skip the first reply since it's the parent message itself
				for _, reply := range replies {
					if reply.TS != msg.TS {
						allMessages = append(allMessages, reply)
					}
				}
			}
		}

		if len(allMessages) == 0 {
			n := channelCount.Add(1)
			e.progressf("Scanning channels: %d/%d (%d%%)", n, total, n*100/int64(total))
			continue
		}

		blob := slBuildChannelBlob(channelName, channelURL, conv.ID, allMessages)
		blobID := types.ComputeBlobID(blob)
		prov := slackProvenance(channelName, conv.ID, channelURL, channelURL)

		n := channelCount.Add(1)
		if total > 0 {
			e.progressf("Scanning channels: %d/%d (%d%%)", n, total, n*100/int64(total))
		} else {
			e.progressf("Scanning channels: %d", n)
		}

		if err := callback(blob, blobID, prov); err != nil {
			return err
		}
	}

	if total > 0 {
		e.progressf("Scanning channels: %d/%d (100%%)\n", channelCount.Load(), total)
	}

	e.logf("Scanned %d channels", channelCount.Load())
	return nil
}
