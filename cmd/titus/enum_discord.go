package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	discordToken     string
	discordGuilds    string
	discordChannels  string
	discordRateLimit float64
)

var discordCmd = &cobra.Command{
	Use:   "discord",
	Short: "Scan Discord servers for secrets",
	Long: `Scan Discord servers for secrets via the Bot API.
Enumerates channel messages, pinned messages, and threads.

Authentication:
  Use --token with a Discord Bot token.

Examples:
  titus enum discord --token BOT_TOKEN
  DISCORD_TOKEN=BOT_TOKEN titus enum discord
  titus enum discord --token BOT_TOKEN --guilds guildId1,guildId2 --channels chId1`,
	RunE: runDiscordEnumScan,
}

func registerDiscordFlags(fs *pflag.FlagSet) {
	fs.StringVar(&discordToken, "token", "", "Discord Bot token (or DISCORD_TOKEN env)")
	fs.StringVar(&discordGuilds, "guilds", "", "Comma-separated guild/server IDs to scan (default: all)")
	fs.StringVar(&discordChannels, "channels", "", "Comma-separated channel IDs to scan (default: all text channels)")
	fs.Float64Var(&discordRateLimit, "rate-limit", 2.0, "Requests per second")
}

func init() {
	registerDiscordFlags(discordCmd.Flags())
}

func runDiscordEnumScan(cmd *cobra.Command, args []string) error {
	token := discordToken
	if token == "" {
		token = os.Getenv("DISCORD_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("discord bot token is required: use --token or DISCORD_TOKEN env var")
	}

	var guilds []string
	if discordGuilds != "" {
		for _, g := range strings.Split(discordGuilds, ",") {
			g = strings.TrimSpace(g)
			if g != "" {
				guilds = append(guilds, g)
			}
		}
	}

	var channels []string
	if discordChannels != "" {
		for _, c := range strings.Split(discordChannels, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				channels = append(channels, c)
			}
		}
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewDiscordEnumerator(enum.DiscordConfig{
		Token:     token,
		Guilds:    guilds,
		Channels:  channels,
		RateLimit: discordRateLimit,
		Verbose:   verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Discord enumerator: %w", err)
	}

	return runEnumScan(cmd, enumerator, "Discord")
}
