package rule

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDiscordWebhookRule_SnowflakeLength checks that kingfisher.discord.1
// reports webhooks whatever the digit count of their snowflake ID. Discord
// IDs are 64-bit snowflakes: those created since mid-2022 have 19 digits and
// the oldest ones have 17, so a fixed 18-digit ID misses most webhooks
// created today.
func TestDiscordWebhookRule_SnowflakeLength(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)

	var rule *types.Rule
	for _, r := range rules {
		if r.ID == "kingfisher.discord.1" {
			rule = r
			break
		}
	}
	require.NotNil(t, rule, "kingfisher.discord.1 should exist")

	// The token is built here so the test file does not carry anything that
	// looks like a real webhook.
	token := strings.Repeat("aB3_-xYz9Q", 7)[:68]

	testCases := []struct {
		name string
		id   string
		want bool
	}{
		{name: "17-digit ID (2015)", id: "81384788765712384", want: true},
		{name: "18-digit ID", id: "123456789012345678", want: true},
		{name: "19-digit ID (since 2022)", id: "1234567890123456789", want: true},
		{name: "20-digit ID", id: "12345678901234567890", want: true},
		{name: "16-digit ID", id: "1234567890123456", want: false},
		{name: "21-digit ID", id: "123456789012345678901", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := matcher.NewPortableRegexp([]*types.Rule{rule}, 0, nil)
			require.NoError(t, err)

			url := "https://discord.com/api/webhooks/" + tc.id + "/" + token
			content := []byte("DISCORD_WEBHOOK_URL=" + url + "\n")
			matches, err := m.Match(content)
			require.NoError(t, err)

			if !tc.want {
				assert.Empty(t, matches, "expected no match for %s", tc.id)
				return
			}

			require.Len(t, matches, 1, "expected one match for %s", tc.id)
			assert.Equal(t, url, string(matches[0].Snippet.Matching))
			assert.Equal(t, token, string(matches[0].NamedGroups["webhook_token"]))
			assert.Equal(t, "https://discord.com/api/webhooks/"+tc.id, string(matches[0].NamedGroups["webhook_base"]))
		})
	}
}
