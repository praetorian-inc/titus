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
	trelloAPIKey    string
	trelloToken     string
	trelloBoards    string
	trelloRateLimit float64
)

var trelloCmd = &cobra.Command{
	Use:   "trello",
	Short: "Scan Trello boards for secrets",
	Long: `Scan Trello boards for secrets via the REST API.
Enumerates cards, comments, and checklists across boards.

Authentication:
  Use --api-key and --token (Trello Power-Up API key + user token).

Examples:
  titus enum trello --api-key KEY --token TOKEN
  TRELLO_API_KEY=KEY TRELLO_TOKEN=TOKEN titus enum trello
  titus enum trello --api-key KEY --token TOKEN --boards boardId1,boardId2`,
	RunE: runTrelloEnumScan,
}

func registerTrelloFlags(fs *pflag.FlagSet) {
	fs.StringVar(&trelloAPIKey, "api-key", "", "Trello API key (or TRELLO_API_KEY env)")
	fs.StringVar(&trelloToken, "token", "", "Trello user token (or TRELLO_TOKEN env)")
	fs.StringVar(&trelloBoards, "boards", "", "Comma-separated board IDs to scan (default: all)")
	fs.Float64Var(&trelloRateLimit, "rate-limit", 3.0, "Requests per second")
}

func init() {
	registerTrelloFlags(trelloCmd.Flags())
}

func runTrelloEnumScan(cmd *cobra.Command, args []string) error {
	apiKey := trelloAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("TRELLO_API_KEY")
	}
	if apiKey == "" {
		return fmt.Errorf("trello API key is required: use --api-key or TRELLO_API_KEY env var")
	}

	token := trelloToken
	if token == "" {
		token = os.Getenv("TRELLO_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("trello token is required: use --token or TRELLO_TOKEN env var")
	}

	var boards []string
	if trelloBoards != "" {
		for _, b := range strings.Split(trelloBoards, ",") {
			b = strings.TrimSpace(b)
			if b != "" {
				boards = append(boards, b)
			}
		}
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewTrelloEnumerator(enum.TrelloConfig{
		APIKey:    apiKey,
		Token:     token,
		Boards:    boards,
		RateLimit: trelloRateLimit,
		Verbose:   verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Trello enumerator: %w", err)
	}

	return runEnumScan(cmd, enumerator, "Trello")
}
