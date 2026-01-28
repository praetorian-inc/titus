package main

import (
	"github.com/spf13/cobra"
)

var (
	verbose bool
	quiet   bool
)

var rootCmd = &cobra.Command{
	Use:   "titus",
	Short: "Titus - Go port of NoseyParker secrets scanner",
	Long: `Titus is a fast secrets scanner that finds credentials in code, files, and git history.
It uses regex-based detection rules to identify sensitive data like API keys, passwords, and tokens.

This is a Go port of the original NoseyParker tool.`,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode (errors only)")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(githubCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(mergeCmd)
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
