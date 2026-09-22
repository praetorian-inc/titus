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
	zendeskSubdomain string
	zendeskEmail     string
	zendeskToken     string
	zendeskRateLimit float64
)

var zendeskCmd = &cobra.Command{
	Use:   "zendesk",
	Short: "Scan a Zendesk instance for secrets",
	Long: `Scan a Zendesk instance for secrets via the REST API v2.
Enumerates support tickets (with comments) and help center articles.

Authentication:
  Use --email and --token with a Zendesk API token.
  Create an API token at: Admin > Channels > API

Examples:
  titus enum zendesk --subdomain mycompany --email agent@example.com --token abc123
  ZENDESK_SUBDOMAIN=mycompany ZENDESK_EMAIL=agent@example.com ZENDESK_TOKEN=abc123 titus enum zendesk`,
	RunE: runZendeskEnumScan,
}

func registerZendeskFlags(fs *pflag.FlagSet) {
	fs.StringVar(&zendeskSubdomain, "subdomain", "", "Zendesk subdomain (or ZENDESK_SUBDOMAIN env)")
	fs.StringVar(&zendeskEmail, "email", "", "Agent email address (or ZENDESK_EMAIL env)")
	fs.StringVar(&zendeskToken, "token", "", "Zendesk API token (or ZENDESK_TOKEN env)")
	fs.Float64Var(&zendeskRateLimit, "rate-limit", 3.0, "Requests per second")
}

func init() {
	registerZendeskFlags(zendeskCmd.Flags())
}

func runZendeskEnumScan(cmd *cobra.Command, args []string) error {
	subdomain := zendeskSubdomain
	if subdomain == "" {
		subdomain = os.Getenv("ZENDESK_SUBDOMAIN")
	}
	if subdomain == "" {
		return fmt.Errorf("zendesk subdomain is required: use --subdomain or ZENDESK_SUBDOMAIN env var")
	}

	email := zendeskEmail
	if email == "" {
		email = os.Getenv("ZENDESK_EMAIL")
	}
	if email == "" {
		return fmt.Errorf("zendesk email is required: use --email or ZENDESK_EMAIL env var")
	}

	token := zendeskToken
	if token == "" {
		token = os.Getenv("ZENDESK_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("zendesk API token is required: use --token or ZENDESK_TOKEN env var")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewZendeskEnumerator(enum.ZendeskConfig{
		Subdomain: subdomain,
		Email:     email,
		Token:     token,
		RateLimit: zendeskRateLimit,
		Verbose:   verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Zendesk enumerator: %w", err)
	}

	return runEnumScan(cmd, enumerator, "Zendesk")
}
