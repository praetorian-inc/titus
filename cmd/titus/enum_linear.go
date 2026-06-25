package main

import (
	"fmt"
	"io"
	"os"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var linearToken string

var linearCmd = &cobra.Command{
	Use:   "linear",
	Short: "Scan a Linear workspace for secrets",
	Long: `Scan an entire Linear workspace for secrets via the GraphQL API.
Enumerates issues (with comments), documents, and project updates.

Authentication:
  Use --token or LINEAR_TOKEN env var with a Linear API key.
  Create one at: https://linear.app/settings/api

Examples:
  titus enum linear --token lin_api_xxx
  LINEAR_TOKEN=lin_api_xxx titus enum linear
  titus enum linear --token lin_api_xxx --output linear-scan.db --format json`,
	RunE: runLinearScan,
}

// registerLinearFlags registers Linear-specific flags on the given FlagSet.
func registerLinearFlags(fs *pflag.FlagSet) {
	fs.StringVar(&linearToken, "token", "", "Linear API key (or LINEAR_TOKEN env)")
}

func init() {
	registerLinearFlags(linearCmd.Flags())
}

func runLinearScan(cmd *cobra.Command, args []string) error {
	token := linearToken
	if token == "" {
		token = os.Getenv("LINEAR_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("linear API key is required: use --token or LINEAR_TOKEN env var")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewLinearEnumerator(enum.LinearConfig{
		Token:   token,
		Verbose: verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Linear enumerator: %w", err)
	}

	return runEnumScan(cmd, enumerator, "Linear")
}
