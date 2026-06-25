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
	jiraToken         string
	jiraUsername      string
	jiraBaseURL       string
	jiraProjects      string
	jiraRateLimit     float64
	jiraAllowInsecure bool
)

var jiraCmd = &cobra.Command{
	Use:   "jira",
	Short: "Scan a Jira instance for secrets",
	Long: `Scan an entire Jira instance for secrets via the REST API.
Enumerates issue descriptions and comments across all projects.
Supports both Jira Cloud (API v3) and Jira Server/Data Center (API v2),
with automatic version detection.

Authentication:
  For Jira Cloud: use --username and --token with an API token.
  For Jira Server/Data Center: use --token with a PAT (Personal Access Token).
  Create a Cloud API token at: https://id.atlassian.com/manage-profile/security/api-tokens

Examples:
  titus enum jira --base-url https://mysite.atlassian.net --username user@example.com --token ATATT...
  JIRA_BASE_URL=https://mysite.atlassian.net JIRA_USERNAME=user@example.com JIRA_TOKEN=ATATT... titus enum jira
  titus enum jira --base-url https://jira.internal --token PAT_TOKEN --projects DEV,OPS
  titus enum jira --base-url http://jira.local:8080 --token PAT --allow-insecure`,
	RunE: runJiraScan,
}

// registerJiraFlags registers Jira-specific flags on the given FlagSet.
func registerJiraFlags(fs *pflag.FlagSet) {
	fs.StringVar(&jiraToken, "token", "", "Jira API token or PAT (or JIRA_TOKEN env)")
	fs.StringVar(&jiraUsername, "username", "", "Jira username for Cloud basic auth (or JIRA_USERNAME env)")
	fs.StringVar(&jiraBaseURL, "base-url", "", "Jira base URL (or JIRA_BASE_URL env)")
	fs.StringVar(&jiraProjects, "projects", "", "Comma-separated project keys to scan (empty = all)")
	fs.Float64Var(&jiraRateLimit, "rate-limit", 5.0, "Requests per second")
	fs.BoolVar(&jiraAllowInsecure, "allow-insecure", false, "Allow plaintext HTTP base URLs (for internal instances)")
}

func init() {
	registerJiraFlags(jiraCmd.Flags())
}

func runJiraScan(cmd *cobra.Command, args []string) error {
	token := jiraToken
	if token == "" {
		token = os.Getenv("JIRA_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("jira API token is required: use --token or JIRA_TOKEN env var")
	}

	username := jiraUsername
	if username == "" {
		username = os.Getenv("JIRA_USERNAME")
	}

	baseURL := jiraBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("JIRA_BASE_URL")
	}
	if baseURL == "" {
		return fmt.Errorf("jira base URL is required: use --base-url or JIRA_BASE_URL env var")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewJiraEnumerator(enum.JiraConfig{
		Token:             token,
		Username:          username,
		BaseURL:           baseURL,
		RateLimit:         jiraRateLimit,
		Projects:          jiraProjects,
		AllowInsecureHTTP: jiraAllowInsecure,
		Verbose:           verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Jira enumerator: %w", err)
	}

	return runEnumScan(cmd, enumerator, "Jira")
}
