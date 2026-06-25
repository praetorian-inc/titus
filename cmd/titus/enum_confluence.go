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
	confluenceToken     string
	confluenceUsername  string
	confluenceBaseURL   string
	confluenceSpaces    string
	confluenceRateLimit float64
)

var confluenceCmd = &cobra.Command{
	Use:   "confluence",
	Short: "Scan a Confluence instance for secrets",
	Long: `Scan an entire Confluence instance for secrets via the REST API.
Enumerates pages, blog posts, and comments across all spaces.

Authentication:
  For Confluence Cloud: use --username and --token with an API token.
  For Confluence Server/Data Center: use --token with a PAT (Personal Access Token).
  Create a Cloud API token at: https://id.atlassian.com/manage-profile/security/api-tokens

Examples:
  titus enum confluence --base-url https://mysite.atlassian.net/wiki --username user@example.com --token ATATT...
  CONFLUENCE_BASE_URL=https://mysite.atlassian.net/wiki CONFLUENCE_USERNAME=user@example.com CONFLUENCE_TOKEN=ATATT... titus enum confluence
  titus enum confluence --base-url https://confluence.internal --token PAT_TOKEN --spaces DEV,OPS`,
	RunE: runConfluenceScan,
}

// registerConfluenceFlags registers Confluence-specific flags on the given FlagSet.
func registerConfluenceFlags(fs *pflag.FlagSet) {
	fs.StringVar(&confluenceToken, "token", "", "Confluence API token or PAT (or CONFLUENCE_TOKEN env)")
	fs.StringVar(&confluenceUsername, "username", "", "Confluence username for Cloud basic auth (or CONFLUENCE_USERNAME env)")
	fs.StringVar(&confluenceBaseURL, "base-url", "", "Confluence base URL (or CONFLUENCE_BASE_URL env)")
	fs.StringVar(&confluenceSpaces, "spaces", "", "Comma-separated space keys to scan (empty = all)")
	fs.Float64Var(&confluenceRateLimit, "rate-limit", 5.0, "Requests per second")
}

func init() {
	registerConfluenceFlags(confluenceCmd.Flags())
}

func runConfluenceScan(cmd *cobra.Command, args []string) error {
	token := confluenceToken
	if token == "" {
		token = os.Getenv("CONFLUENCE_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("confluence API token is required: use --token or CONFLUENCE_TOKEN env var")
	}

	username := confluenceUsername
	if username == "" {
		username = os.Getenv("CONFLUENCE_USERNAME")
	}

	baseURL := confluenceBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("CONFLUENCE_BASE_URL")
	}
	if baseURL == "" {
		return fmt.Errorf("confluence base URL is required: use --base-url or CONFLUENCE_BASE_URL env var")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewConfluenceEnumerator(enum.ConfluenceConfig{
		Token:     token,
		Username:  username,
		BaseURL:   baseURL,
		RateLimit: confluenceRateLimit,
		Spaces:    confluenceSpaces,
		Verbose:   verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Confluence enumerator: %w", err)
	}

	return runEnumScan(cmd, enumerator, "Confluence")
}
