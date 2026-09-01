package enum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDiscordEnumerator(t *testing.T, handler http.Handler) *DiscordEnumerator {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	e, err := NewDiscordEnumerator(DiscordConfig{
		Token:     "test-bot-token",
		RateLimit: 100,
	})
	require.NoError(t, err)
	e.apiBase = srv.URL
	return e
}

func TestNewDiscordEnumerator(t *testing.T) {
	e, err := NewDiscordEnumerator(DiscordConfig{
		Token: "tok",
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestNewDiscordEnumerator_MissingToken(t *testing.T) {
	_, err := NewDiscordEnumerator(DiscordConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bot token is required")
}

func TestNewDiscordEnumerator_DefaultRateLimit(t *testing.T) {
	e, err := NewDiscordEnumerator(DiscordConfig{
		Token: "tok",
	})
	require.NoError(t, err)
	assert.Equal(t, 2.0, e.config.RateLimit)
}

func TestDiscordProvenance(t *testing.T) {
	prov := discordProvenance("channel", "ch123", "#general", "https://discord.com/channels/g1/ch123")

	assert.Equal(t, "discord", prov.Payload["source"])
	assert.Equal(t, "channel", prov.Payload["entityType"])
	assert.Equal(t, "ch123", prov.Payload["identifier"])
	assert.Equal(t, "#general", prov.Payload["title"])
	assert.Equal(t, "https://discord.com/channels/g1/ch123", prov.Payload["url"])
}

func TestDiscordAuth_BotHeader(t *testing.T) {
	var gotAuth string
	e := testDiscordEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("[]"))
	}))

	_, _ = e.discordGet(context.Background(), "/test")
	assert.Equal(t, "Bot test-bot-token", gotAuth)
}

func TestDiscordBuildChannelBlob(t *testing.T) {
	messages := []discordMessage{
		{
			ID:        "m1",
			Content:   "hello world",
			Timestamp: "2024-01-01T00:00:00Z",
			Author:    struct{ Username string `json:"username"` }{Username: "alice"},
		},
		{
			ID:        "m2",
			Content:   "secret: abc123",
			Timestamp: "2024-01-01T00:01:00Z",
			Author:    struct{ Username string `json:"username"` }{Username: "bob"},
		},
	}
	blob := discordBuildChannelBlob("My Server", "general", messages)
	s := string(blob)

	assert.Contains(t, s, "Server: My Server")
	assert.Contains(t, s, "Channel: #general")
	assert.Contains(t, s, "hello world")
	assert.Contains(t, s, "secret: abc123")
	assert.Contains(t, s, "alice")
	assert.Contains(t, s, "bob")
}

func TestDiscordBuildChannelBlob_SkipsEmpty(t *testing.T) {
	messages := []discordMessage{
		{ID: "m1", Content: "", Author: struct{ Username string `json:"username"` }{Username: "alice"}},
		{ID: "m2", Content: "has content", Author: struct{ Username string `json:"username"` }{Username: "bob"}},
	}
	blob := discordBuildChannelBlob("S", "ch", messages)
	s := string(blob)

	assert.NotContains(t, s, "alice")
	assert.Contains(t, s, "has content")
}

func TestDiscordBuildPinsBlob(t *testing.T) {
	pins := []discordMessage{
		{
			ID:        "p1",
			Content:   "pinned secret",
			Timestamp: "2024-01-01T00:00:00Z",
			Author:    struct{ Username string `json:"username"` }{Username: "admin"},
			Pinned:    true,
		},
	}
	blob := discordBuildPinsBlob("Server", "general", pins)
	s := string(blob)

	assert.Contains(t, s, "(pinned)")
	assert.Contains(t, s, "pinned secret")
}

func TestIsTextChannel(t *testing.T) {
	assert.True(t, isTextChannel(0))   // GUILD_TEXT
	assert.True(t, isTextChannel(5))   // GUILD_ANNOUNCEMENT
	assert.True(t, isTextChannel(15))  // GUILD_FORUM
	assert.False(t, isTextChannel(2))  // GUILD_VOICE
	assert.False(t, isTextChannel(4))  // GUILD_CATEGORY
	assert.False(t, isTextChannel(13)) // GUILD_STAGE_VOICE
}

func TestDiscordFetchGuilds(t *testing.T) {
	guilds := []discordGuild{
		{ID: "g1", Name: "Server One"},
		{ID: "g2", Name: "Server Two"},
	}
	e := testDiscordEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users/@me/guilds" {
			_ = json.NewEncoder(w).Encode(guilds)
			return
		}
		w.WriteHeader(404)
	}))

	result, err := e.discordFetchGuilds(context.Background())
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "Server One", result[0].Name)
}

func TestDiscordFetchChannels(t *testing.T) {
	channels := []discordChannel{
		{ID: "ch1", Name: "general", Type: 0, GuildID: "g1"},
		{ID: "ch2", Name: "voice", Type: 2, GuildID: "g1"},
	}
	e := testDiscordEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/guilds/g1/channels") {
			_ = json.NewEncoder(w).Encode(channels)
			return
		}
		w.WriteHeader(404)
	}))

	result, err := e.discordFetchChannels(context.Background(), "g1")
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestDiscordFetchMessages(t *testing.T) {
	messages := []discordMessage{
		{ID: "m1", Content: "hello", Author: struct{ Username string `json:"username"` }{Username: "user1"}},
	}
	e := testDiscordEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/channels/ch1/messages") {
			assert.Equal(t, "100", r.URL.Query().Get("limit"))
			_ = json.NewEncoder(w).Encode(messages)
			return
		}
		w.WriteHeader(404)
	}))

	result, err := e.discordFetchMessages(context.Background(), "ch1", "", 100)
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestDiscordFetchMessages_Pagination(t *testing.T) {
	e := testDiscordEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/channels/ch1/messages") {
			before := r.URL.Query().Get("before")
			if before == "" {
				_ = json.NewEncoder(w).Encode([]discordMessage{
					{ID: "m2", Content: "newer"},
					{ID: "m1", Content: "older"},
				})
			} else if before == "m1" {
				_ = json.NewEncoder(w).Encode([]discordMessage{})
			}
			return
		}
		w.WriteHeader(404)
	}))

	result, err := e.discordFetchAllMessages(context.Background(), "ch1")
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestDiscordFetchPins(t *testing.T) {
	pins := []discordMessage{
		{ID: "p1", Content: "pinned", Pinned: true, Author: struct{ Username string `json:"username"` }{Username: "admin"}},
	}
	e := testDiscordEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/channels/ch1/pins") {
			_ = json.NewEncoder(w).Encode(pins)
			return
		}
		w.WriteHeader(404)
	}))

	result, err := e.discordFetchPins(context.Background(), "ch1")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "pinned", result[0].Content)
}

func TestDiscordEnumerate_EndToEnd(t *testing.T) {
	guilds := []discordGuild{{ID: "g1", Name: "Test Server"}}
	channels := []discordChannel{
		{ID: "ch1", Name: "general", Type: 0, GuildID: "g1"},
		{ID: "ch2", Name: "voice", Type: 2, GuildID: "g1"},
	}
	messages := []discordMessage{
		{ID: "m1", Content: "secret data here", Timestamp: "2024-01-01T00:00:00Z",
			Author: struct{ Username string `json:"username"` }{Username: "alice"}},
	}
	pins := []discordMessage{
		{ID: "p1", Content: "pinned cred", Timestamp: "2024-01-01T00:00:00Z", Pinned: true,
			Author: struct{ Username string `json:"username"` }{Username: "admin"}},
	}

	e := testDiscordEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/users/@me/guilds":
			_ = json.NewEncoder(w).Encode(guilds)
		case strings.Contains(r.URL.Path, "/guilds/g1/channels"):
			_ = json.NewEncoder(w).Encode(channels)
		case strings.Contains(r.URL.Path, "/channels/ch1/messages"):
			_ = json.NewEncoder(w).Encode(messages)
		case strings.Contains(r.URL.Path, "/channels/ch1/pins"):
			_ = json.NewEncoder(w).Encode(pins)
		default:
			w.WriteHeader(404)
		}
	}))

	var blobs []string
	var provs []types.Provenance
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		provs = append(provs, prov)
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, blobs, 2) // messages blob + pins blob
	assert.Contains(t, blobs[0], "secret data here")
	assert.Contains(t, blobs[1], "pinned cred")

	ep := provs[0].(types.ExtendedProvenance)
	assert.Equal(t, "discord", ep.Payload["source"])
	assert.Equal(t, "channel", ep.Payload["entityType"])
}

func TestDiscordEnumerate_GuildFilter(t *testing.T) {
	guilds := []discordGuild{
		{ID: "g1", Name: "Include"},
		{ID: "g2", Name: "Exclude"},
	}
	channels := []discordChannel{
		{ID: "ch1", Name: "text", Type: 0},
	}
	messages := []discordMessage{
		{ID: "m1", Content: "data", Author: struct{ Username string `json:"username"` }{Username: "u"}},
	}

	e := testDiscordEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/users/@me/guilds":
			_ = json.NewEncoder(w).Encode(guilds)
		case strings.Contains(r.URL.Path, "/guilds/g1/channels"):
			_ = json.NewEncoder(w).Encode(channels)
		case strings.Contains(r.URL.Path, "/channels/ch1/messages"):
			_ = json.NewEncoder(w).Encode(messages)
		case strings.Contains(r.URL.Path, "/channels/ch1/pins"):
			_ = json.NewEncoder(w).Encode([]discordMessage{})
		default:
			w.WriteHeader(404)
		}
	}))
	e.config.Guilds = []string{"g1"}

	var count int
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestDiscordEnumerate_ChannelFilter(t *testing.T) {
	guilds := []discordGuild{{ID: "g1", Name: "Server"}}
	channels := []discordChannel{
		{ID: "ch1", Name: "include", Type: 0},
		{ID: "ch2", Name: "exclude", Type: 0},
	}
	messages := []discordMessage{
		{ID: "m1", Content: "data", Author: struct{ Username string `json:"username"` }{Username: "u"}},
	}

	e := testDiscordEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/users/@me/guilds":
			_ = json.NewEncoder(w).Encode(guilds)
		case strings.Contains(r.URL.Path, "/guilds/g1/channels"):
			_ = json.NewEncoder(w).Encode(channels)
		case strings.Contains(r.URL.Path, "/channels/ch1/messages"):
			_ = json.NewEncoder(w).Encode(messages)
		case strings.Contains(r.URL.Path, "/channels/ch1/pins"):
			_ = json.NewEncoder(w).Encode([]discordMessage{})
		default:
			w.WriteHeader(404)
		}
	}))
	e.config.Channels = []string{"ch1"}

	var count int
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestDiscordEnumerate_ErrorResilience(t *testing.T) {
	guilds := []discordGuild{{ID: "g1", Name: "Server"}}
	channels := []discordChannel{
		{ID: "ch1", Name: "text", Type: 0},
	}

	e := testDiscordEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/users/@me/guilds":
			_ = json.NewEncoder(w).Encode(guilds)
		case strings.Contains(r.URL.Path, "/guilds/g1/channels"):
			_ = json.NewEncoder(w).Encode(channels)
		case strings.Contains(r.URL.Path, "/channels/ch1/messages"):
			w.WriteHeader(403)
		case strings.Contains(r.URL.Path, "/channels/ch1/pins"):
			w.WriteHeader(403)
		default:
			w.WriteHeader(404)
		}
	}))

	var count int
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enumeration errors")
	assert.Equal(t, 0, count)
}
