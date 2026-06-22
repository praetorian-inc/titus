package enum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	Token     string    // Slack API token (xoxb-..., xoxp-..., or xoxc-...)
	Cookie    string    // Session cookie (xoxd-...) — required when using xoxc- tokens
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
	if strings.HasPrefix(cfg.Token, "xoxc-") && cfg.Cookie == "" {
		return nil, fmt.Errorf("xoxc- tokens require a session cookie (--cookie with xoxd-... value)")
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

// slackProvenance builds an ExtendedProvenance for a Slack message.
func slackProvenance(channel, channelID, messageURL, author string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":  "slack",
			"channel": channel,
			"author":  author,
			"url":     messageURL,
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
	IsMember   bool   `json:"is_member"`
}

// slAttachment represents a Slack message attachment.
type slAttachment struct {
	Text     string `json:"text"`
	Fallback string `json:"fallback"`
}

// slMessage represents a Slack message.
type slMessage struct {
	Type        string         `json:"type"`
	User        string         `json:"user"`
	Text        string         `json:"text"`
	TS          string         `json:"ts"`
	ReplyCount  int            `json:"reply_count"`
	Attachments []slAttachment `json:"attachments,omitempty"`
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
		if e.config.Cookie != "" {
			cookie := e.config.Cookie
			if !strings.HasPrefix(cookie, "d=") {
				cookie = "d=" + cookie
			}
			req.Header.Set("Cookie", cookie)
		}

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
			endpoint += "&cursor=" + url.QueryEscape(cursor)
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

		for _, ch := range resp.Channels {
			if ch.IsMember {
				all = append(all, ch)
			}
		}

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
			endpoint += "&cursor=" + url.QueryEscape(cursor)
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
			endpoint += "&cursor=" + url.QueryEscape(cursor)
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

// slBuildMessageBlob assembles a single message and its thread replies into a blob.
func slBuildMessageBlob(channelName, messageURL, channelID string, msg slMessage, replies []slMessage, userNames map[string]string) []byte {
	var sb strings.Builder
	sb.WriteString("Channel: " + channelName + "\n")
	sb.WriteString("URL: " + messageURL + "\n")
	sb.WriteString("ID: " + channelID + "\n")
	sb.WriteString("---\n")
	slWriteMessage(&sb, msg, userNames)
	for _, reply := range replies {
		slWriteMessage(&sb, reply, userNames)
	}
	return []byte(sb.String())
}

// slWriteMessage writes a single message's text and attachment content to a builder.
func slWriteMessage(sb *strings.Builder, msg slMessage, userNames map[string]string) {
	author := msg.User
	if name, ok := userNames[msg.User]; ok {
		author = name
	}
	sb.WriteString("[" + author + "] [" + msg.TS + "]: " + msg.Text + "\n")
	for _, att := range msg.Attachments {
		if att.Text != "" {
			sb.WriteString("  [attachment]: " + att.Text + "\n")
		}
		if att.Fallback != "" && att.Fallback != att.Text {
			sb.WriteString("  [attachment-fallback]: " + att.Fallback + "\n")
		}
	}
}

// slMessagePermalink builds a deep link to a specific Slack message.
// Format: https://{team}.slack.com/archives/{channelID}/p{timestamp_without_dot}
func slMessagePermalink(teamDomain, channelID, ts string) string {
	if teamDomain == "" {
		return ""
	}
	tsNoDot := strings.ReplaceAll(ts, ".", "")
	return teamDomain + "/archives/" + channelID + "/p" + tsNoDot
}

// slChannelURL returns the Slack web URL for a channel.
func slChannelURL(channelID string) string {
	return "https://app.slack.com/client/" + channelID
}

// slFetchUserNames builds a user ID to display name lookup by paginating users.list.
func (e *SlackEnumerator) slFetchUserNames(ctx context.Context) map[string]string {
	names := make(map[string]string)
	cursor := ""
	for {
		endpoint := "users.list?limit=200"
		if cursor != "" {
			endpoint += "&cursor=" + url.QueryEscape(cursor)
		}
		body, err := e.slGet(ctx, endpoint)
		if err != nil {
			break
		}
		var resp struct {
			OK      bool `json:"ok"`
			Members []struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				Profile struct {
					DisplayName string `json:"display_name"`
					RealName    string `json:"real_name"`
				} `json:"profile"`
			} `json:"members"`
			ResponseMetadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if json.Unmarshal(body, &resp) != nil || !resp.OK {
			break
		}
		for _, m := range resp.Members {
			name := m.Profile.DisplayName
			if name == "" {
				name = m.Profile.RealName
			}
			if name == "" {
				name = m.Name
			}
			names[m.ID] = name
		}
		cursor = resp.ResponseMetadata.NextCursor
		if cursor == "" {
			break
		}
	}
	return names
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

// slIsAccessError returns true if the error string indicates a channel access
// issue that should be skipped rather than aborting the entire scan.
func slIsAccessError(errMsg string) bool {
	switch {
	case strings.Contains(errMsg, "not_in_channel"),
		strings.Contains(errMsg, "channel_not_found"),
		strings.Contains(errMsg, "account_inactive"),
		strings.Contains(errMsg, "is_archived"),
		strings.Contains(errMsg, "missing_scope"):
		return true
	}
	return false
}

// Enumerate discovers content from a Slack workspace and yields blobs.
func (e *SlackEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Get workspace info for building message permalinks
	teamDomain := ""
	authBody, err := e.slGet(ctx, "auth.test")
	if err == nil {
		var authResp struct {
			OK  bool   `json:"ok"`
			URL string `json:"url"`
		}
		if json.Unmarshal(authBody, &authResp) == nil && authResp.OK {
			teamDomain = strings.TrimSuffix(authResp.URL, "/")
		}
	}

	e.logf("Listing conversations...")

	conversations, err := e.slListConversations(ctx)
	if err != nil {
		return fmt.Errorf("listing conversations: %w", err)
	}

	conversations = slFilterChannels(conversations, e.config.Channels)

	total := len(conversations)
	e.logf("Found %d conversations, scanning for secrets...", total)

	// Build user lookup for display names
	e.logf("Fetching user directory...")
	userNames := e.slFetchUserNames(ctx)
	e.logf("Loaded %d users", len(userNames))

	var channelCount atomic.Int64

	for _, conv := range conversations {
		channelName := conv.Name
		if channelName == "" {
			channelName = conv.ID
		}

		// Fetch channel history; skip inaccessible channels
		messages, err := e.slFetchHistory(ctx, conv.ID)
		if err != nil {
			if slIsAccessError(err.Error()) {
				e.logf("Skipping channel %s: %v", channelName, err)
				channelCount.Add(1)
				continue
			}
			return fmt.Errorf("fetching history for %s: %w", channelName, err)
		}

		// Emit one blob per message (with thread replies inline)
		for _, msg := range messages {
			var replies []slMessage
			if msg.ReplyCount > 0 {
				threadReplies, err := e.slFetchReplies(ctx, conv.ID, msg.TS)
				if err != nil {
					if slIsAccessError(err.Error()) {
						e.logf("Skipping replies for %s/%s: %v", channelName, msg.TS, err)
					} else {
						e.logf("Error fetching replies for %s/%s: %v", channelName, msg.TS, err)
					}
					// Continue with the message itself, without replies
				} else {
					// Skip the parent message from replies since it duplicates msg
					for _, reply := range threadReplies {
						if reply.TS != msg.TS {
							replies = append(replies, reply)
						}
					}
				}
			}

			// Resolve author name
			authorName := msg.User
			if name, ok := userNames[msg.User]; ok {
				authorName = name
			}

			// Build message permalink
			messageURL := slMessagePermalink(teamDomain, conv.ID, msg.TS)
			if messageURL == "" {
				messageURL = slChannelURL(conv.ID)
			}

			blob := slBuildMessageBlob(channelName, messageURL, conv.ID, msg, replies, userNames)
			blobID := types.ComputeBlobID(blob)
			prov := slackProvenance(channelName, conv.ID, messageURL, authorName)

			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}

		n := channelCount.Add(1)
		if total > 0 {
			e.progressf("Scanning channels: %d/%d (%d%%)", n, total, n*100/int64(total))
		} else {
			e.progressf("Scanning channels: %d", n)
		}
	}

	if total > 0 {
		e.progressf("Scanning channels: %d/%d (100%%)\n", channelCount.Load(), total)
	}

	e.logf("Scanned %d channels", channelCount.Load())
	return nil
}
