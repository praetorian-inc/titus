package main

import (
	"fmt"
	"io"
	"os"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	slackToken     string
	slackCookie    string
	slackChannels  string
	slackRateLimit float64
)

var slackCmd = &cobra.Command{
	Use:   "slack",
	Short: "Scan a Slack workspace for secrets",
	Long: `Scan an entire Slack workspace for secrets via the Slack Web API.
Enumerates channels, messages, and thread replies.

Authentication:
  Use --token or SLACK_TOKEN env var with a Slack token.
  Supported token types: xoxb- (bot), xoxp- (user), xoxc- (browser session).
  Browser session tokens (xoxc-) also require --cookie with the xoxd- session cookie.
  To get xoxc/xoxd: open Slack in browser → DevTools → Application →
    token: Local Storage → search for xoxc-
    cookie: Cookies → cookie named "d" (starts with xoxd-)

Examples:
  titus enum slack --token xoxb-xxx
  SLACK_TOKEN=xoxb-xxx titus enum slack
  titus enum slack --token xoxb-xxx --channels general,engineering
  titus enum slack --token xoxb-xxx --output slack-scan.db --format json
  titus enum slack --token xoxc-xxx --cookie xoxd-xxx -v          # browser session token`,
	RunE: runSlackScan,
}

// registerSlackFlags registers Slack-specific flags on the given FlagSet.
func registerSlackFlags(fs *pflag.FlagSet) {
	fs.StringVar(&slackToken, "token", "", "Slack API token (or SLACK_TOKEN env)")
	fs.StringVar(&slackCookie, "cookie", "", "Slack session cookie (xoxd-...) — required for xoxc- tokens (or SLACK_COOKIE env)")
	fs.StringVar(&slackChannels, "channels", "", "Comma-separated channel names to scan (default: all)")
	fs.Float64Var(&slackRateLimit, "rate-limit", 0.75, "API requests per second (default 0.75, Slack Tier 3 = 50 req/min)")
}

func init() {
	registerSlackFlags(slackCmd.Flags())
}

func runSlackScan(cmd *cobra.Command, args []string) error {
	token := slackToken
	if token == "" {
		token = os.Getenv("SLACK_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("slack API token is required: use --token or SLACK_TOKEN env var")
	}

	cookie := slackCookie
	if cookie == "" {
		cookie = os.Getenv("SLACK_COOKIE")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewSlackEnumerator(enum.SlackConfig{
		Token:     token,
		Cookie:    cookie,
		RateLimit: slackRateLimit,
		Channels:  slackChannels,
		Verbose:   verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Slack enumerator: %w", err)
	}

	return runEnumScan(cmd, enumerator, "Slack")
}
