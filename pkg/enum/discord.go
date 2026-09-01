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

const discordAPIBase = "https://discord.com/api/v10"

// DiscordConfig configures the Discord enumerator.
type DiscordConfig struct {
	Token     string    // Bot token
	Guilds    []string  // guild IDs to scan (empty = all the bot has access to)
	Channels  []string  // channel IDs to scan (empty = all text channels)
	RateLimit float64   // requests per second (default 2)
	Verbose   io.Writer // progress output (nil = silent)
}

// DiscordEnumerator enumerates blobs from Discord servers via the Bot API.
type DiscordEnumerator struct {
	config  DiscordConfig
	client  *http.Client
	limiter *rate.Limiter
	apiBase string
}

// NewDiscordEnumerator creates a new Discord enumerator.
func NewDiscordEnumerator(cfg DiscordConfig) (*DiscordEnumerator, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("discord bot token is required")
	}

	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 2.0
	}

	return &DiscordEnumerator{
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
		apiBase: discordAPIBase,
	}, nil
}

func discordProvenance(entityType, id, title, recordURL string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":     "discord",
			"entityType": entityType,
			"identifier": id,
			"title":      title,
			"url":        recordURL,
			"path":       recordURL,
		},
	}
}

func (e *DiscordEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
}

func (e *DiscordEnumerator) progressf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s", fmt.Sprintf(format, args...))
	}
}

// discordGet performs a rate-limited GET with Discord Bot auth and retry.
func (e *DiscordEnumerator) discordGet(ctx context.Context, path string) ([]byte, error) {
	const maxAttempts = 3

	reqURL := e.apiBase + path

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bot "+e.config.Token)
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
			return nil, fmt.Errorf("discord API returned %d after %d attempts", resp.StatusCode, maxAttempts)
		}

		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("discord API returned unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
		return body, nil
	}
	return nil, fmt.Errorf("discordGet: exceeded max attempts")
}

type discordGuild struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type discordChannel struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     int    `json:"type"`
	GuildID  string `json:"guild_id"`
	ParentID string `json:"parent_id"`
}

type discordMessage struct {
	ID        string `json:"id"`
	Content   string `json:"content"`
	Author    struct {
		Username string `json:"username"`
	} `json:"author"`
	Timestamp string `json:"timestamp"`
	Pinned    bool   `json:"pinned"`
}

func (e *DiscordEnumerator) discordFetchGuilds(ctx context.Context) ([]discordGuild, error) {
	body, err := e.discordGet(ctx, "/users/@me/guilds")
	if err != nil {
		return nil, fmt.Errorf("fetch guilds: %w", err)
	}

	var guilds []discordGuild
	if err := json.Unmarshal(body, &guilds); err != nil {
		return nil, fmt.Errorf("decode guilds: %w", err)
	}
	return guilds, nil
}

func (e *DiscordEnumerator) discordFetchChannels(ctx context.Context, guildID string) ([]discordChannel, error) {
	path := fmt.Sprintf("/guilds/%s/channels", guildID)
	body, err := e.discordGet(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("fetch channels for guild %s: %w", guildID, err)
	}

	var channels []discordChannel
	if err := json.Unmarshal(body, &channels); err != nil {
		return nil, fmt.Errorf("decode channels for guild %s: %w", guildID, err)
	}
	return channels, nil
}

// discordFetchMessages fetches up to limit messages before the given ID.
// Pass "" for before to start from the newest.
func (e *DiscordEnumerator) discordFetchMessages(ctx context.Context, channelID string, before string, limit int) ([]discordMessage, error) {
	path := fmt.Sprintf("/channels/%s/messages?limit=%d", channelID, limit)
	if before != "" {
		path += "&before=" + before
	}

	body, err := e.discordGet(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("fetch messages for channel %s: %w", channelID, err)
	}

	var messages []discordMessage
	if err := json.Unmarshal(body, &messages); err != nil {
		return nil, fmt.Errorf("decode messages for channel %s: %w", channelID, err)
	}
	return messages, nil
}

func (e *DiscordEnumerator) discordFetchPins(ctx context.Context, channelID string) ([]discordMessage, error) {
	path := fmt.Sprintf("/channels/%s/pins", channelID)
	body, err := e.discordGet(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("fetch pins for channel %s: %w", channelID, err)
	}

	var messages []discordMessage
	if err := json.Unmarshal(body, &messages); err != nil {
		return nil, fmt.Errorf("decode pins for channel %s: %w", channelID, err)
	}
	return messages, nil
}

// discordFetchAllMessages paginates through all messages in a channel.
func (e *DiscordEnumerator) discordFetchAllMessages(ctx context.Context, channelID string) ([]discordMessage, error) {
	const pageSize = 100
	var all []discordMessage
	var before string

	for {
		batch, err := e.discordFetchMessages(ctx, channelID, before, pageSize)
		if err != nil {
			return all, err
		}
		if len(batch) == 0 {
			break
		}
		all = append(all, batch...)
		before = batch[len(batch)-1].ID
		if len(batch) < pageSize {
			break
		}
	}
	return all, nil
}

func discordBuildChannelBlob(guildName, channelName string, messages []discordMessage) []byte {
	var sb strings.Builder
	sb.WriteString("Server: " + guildName + "\n")
	sb.WriteString("Channel: #" + channelName + "\n")
	sb.WriteString("---\n")

	for _, m := range messages {
		if m.Content == "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("\n[%s] %s:\n", m.Timestamp, m.Author.Username))
		sb.WriteString(m.Content + "\n")
	}
	return []byte(sb.String())
}

func discordBuildPinsBlob(guildName, channelName string, pins []discordMessage) []byte {
	var sb strings.Builder
	sb.WriteString("Server: " + guildName + "\n")
	sb.WriteString("Channel: #" + channelName + " (pinned)\n")
	sb.WriteString("---\n")

	for _, m := range pins {
		if m.Content == "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("\n[%s] %s:\n", m.Timestamp, m.Author.Username))
		sb.WriteString(m.Content + "\n")
	}
	return []byte(sb.String())
}

// isTextChannel returns true for channel types that contain readable messages.
func isTextChannel(chType int) bool {
	switch chType {
	case 0:  // GUILD_TEXT
		return true
	case 5:  // GUILD_ANNOUNCEMENT
		return true
	case 15: // GUILD_FORUM
		return true
	default:
		return false
	}
}

// Enumerate discovers content from Discord servers and yields blobs.
func (e *DiscordEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	e.logf("Scanning Discord servers")

	var count atomic.Int64
	var errs []string

	guilds, err := e.discordFetchGuilds(ctx)
	if err != nil {
		return fmt.Errorf("fetching guilds: %w", err)
	}

	if len(e.config.Guilds) > 0 {
		guildSet := make(map[string]bool, len(e.config.Guilds))
		for _, g := range e.config.Guilds {
			guildSet[g] = true
		}
		var filtered []discordGuild
		for _, g := range guilds {
			if guildSet[g.ID] {
				filtered = append(filtered, g)
			}
		}
		guilds = filtered
	}

	e.logf("Found %d guilds", len(guilds))

	channelSet := make(map[string]bool, len(e.config.Channels))
	for _, c := range e.config.Channels {
		channelSet[c] = true
	}

	for _, guild := range guilds {
		channels, err := e.discordFetchChannels(ctx, guild.ID)
		if err != nil {
			errs = append(errs, fmt.Sprintf("guild %s: %v", guild.ID, err))
			continue
		}

		var textChannels []discordChannel
		for _, ch := range channels {
			if !isTextChannel(ch.Type) {
				continue
			}
			if len(channelSet) > 0 && !channelSet[ch.ID] {
				continue
			}
			textChannels = append(textChannels, ch)
		}

		e.logf("Guild %q: %d text channels", guild.Name, len(textChannels))

		for _, ch := range textChannels {
			messages, err := e.discordFetchAllMessages(ctx, ch.ID)
			if err != nil {
				errs = append(errs, fmt.Sprintf("channel %s messages: %v", ch.ID, err))
				messages = nil
			}

			if len(messages) > 0 {
				blob := discordBuildChannelBlob(guild.Name, ch.Name, messages)
				blobID := types.ComputeBlobID(blob)
				channelURL := fmt.Sprintf("https://discord.com/channels/%s/%s", guild.ID, ch.ID)
				prov := discordProvenance("channel", ch.ID, "#"+ch.Name, channelURL)

				n := count.Add(1)
				e.progressf("Scanning channels: %d", n)

				if err := callback(blob, blobID, prov); err != nil {
					return err
				}
			}

			pins, err := e.discordFetchPins(ctx, ch.ID)
			if err != nil {
				errs = append(errs, fmt.Sprintf("channel %s pins: %v", ch.ID, err))
				continue
			}

			if len(pins) > 0 {
				blob := discordBuildPinsBlob(guild.Name, ch.Name, pins)
				blobID := types.ComputeBlobID(blob)
				channelURL := fmt.Sprintf("https://discord.com/channels/%s/%s", guild.ID, ch.ID)
				prov := discordProvenance("pins", ch.ID, "#"+ch.Name+" (pinned)", channelURL)

				count.Add(1)

				if err := callback(blob, blobID, prov); err != nil {
					return err
				}
			}
		}
	}

	e.logf("Scanned %d channel blobs across %d guilds", count.Load(), len(guilds))

	if len(errs) > 0 {
		return fmt.Errorf("enumeration errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
