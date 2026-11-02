package main

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/titus/pkg/types"
)

var (
	verbose bool
	quiet   bool
)

var rootCmd = &cobra.Command{
	Use:   "titus",
	Short: "Titus - Go port of NoseyParker secrets scanner",
	Long: `Titus is a fast secrets scanner that finds credentials in code, files, and git history.
It uses regex-based detection rules to identify sensitive data like API keys, passwords, and tokens.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if !quiet {
			printBanner()
		}
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode (errors only)")

	// Add subcommands
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(enumCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(exploreCmd)
}

// Execute runs the root command. Cobra's own error print is silenced and
// replaced by reportError, which sanitizes the message.
func Execute() error {
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true
	cmd, err := rootCmd.ExecuteC()
	if err != nil {
		reportError(cmd, err)
	}
	return err
}

// reportError prints err the way cobra does, but passes the message through
// types.SanitizeDisplay: an error can carry repository bytes, such as a path
// read from a .git file or a commondir file, and control bytes in it must
// reach the terminal escaped, not raw (O3). The error value is unchanged.
// Cobra prints its help hint only when the command lookup fails, and the
// usage after any other error, a flag error on a group included (R6-2).
func reportError(cmd *cobra.Command, err error) {
	cmd.PrintErrln(cmd.ErrPrefix(), types.SanitizeDisplay(err.Error()))
	if isLookupError(cmd, err) {
		cmd.PrintErrf("Run '%v --help' for usage.\n", cmd.CommandPath())
		return
	}
	cmd.Println(cmd.UsageString())
}

// isLookupError reports whether err came from cobra's command lookup. Find
// fails only in legacyArgs, for the root command with no Args validator,
// and that error is the only one cobra words "unknown command"; a flag error
// on the same command never is (R6-2).
func isLookupError(cmd *cobra.Command, err error) bool {
	return !cmd.HasParent() && cmd.Args == nil && strings.HasPrefix(err.Error(), "unknown command ")
}
