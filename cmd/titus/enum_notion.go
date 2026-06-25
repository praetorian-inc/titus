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
	notionToken       string
	notionConcurrency int
	notionPageID      string
	notionWorkspace   string
	notionTeamspace   string
)

var notionCmd = &cobra.Command{
	Use:   "notion",
	Short: "Scan a Notion workspace for secrets",
	Long: `Scan an entire Notion workspace for secrets using the internal API.
Requires a token_v2 session cookie from an authenticated Notion session.

Authentication:
  Use --token or NOTION_TOKEN env var with a token_v2 session cookie.
  To obtain the token: open Notion in a browser, open DevTools, find the
  token_v2 cookie under Application > Cookies > www.notion.so.

Examples:
  titus enum notion --token <token_v2>
  titus enum notion --token <token_v2> --concurrency 20
  NOTION_TOKEN=<token_v2> titus enum notion --output notion-scan.db
  titus enum notion --token <token_v2> --page https://app.notion.com/p/Page-Title-abc123def456
  titus enum notion --token <token_v2> --page 37da484a-7dc4-80dd-936b-d247d86f7ef7
  titus enum notion --token <token_v2> --teamspace Engineering
  titus enum notion --token <token_v2> --workspace Praetorian --teamspace "Sales & Marketing"`,
	RunE: runNotionScan,
}

// registerNotionFlags registers Notion-specific flags on the given FlagSet.
func registerNotionFlags(fs *pflag.FlagSet) {
	fs.StringVar(&notionToken, "token", "", "Notion token_v2 session cookie (or NOTION_TOKEN env)")
	fs.IntVar(&notionConcurrency, "concurrency", 10, "Number of parallel page fetchers")
	fs.StringVar(&notionPageID, "page", "", "Scan a single page (URL or page ID)")
	fs.StringVar(&notionWorkspace, "workspace", "", "Workspace name or ID (for multi-workspace accounts)")
	fs.StringVar(&notionTeamspace, "teamspace", "", "Scan only pages in this teamspace (name or ID)")
}

func init() {
	registerNotionFlags(notionCmd.Flags())
}

func runNotionScan(cmd *cobra.Command, args []string) error {
	token := notionToken
	if token == "" {
		token = os.Getenv("NOTION_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("notion token_v2 is required: use --token or NOTION_TOKEN env var")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewNotionEnumerator(enum.NotionConfig{
		Token:       token,
		Concurrency: notionConcurrency,
		Verbose:     verboseWriter,
		PageID:      notionPageID,
		Workspace:   notionWorkspace,
		Teamspace:   notionTeamspace,
	})
	if err != nil {
		return fmt.Errorf("creating Notion enumerator: %w", err)
	}

	return runEnumScan(cmd, enumerator, "Notion")
}
