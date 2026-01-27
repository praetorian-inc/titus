package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

const version = "0.1.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  "Display the version of Titus (Go port of NoseyParker)",
	RunE:  runVersion,
}

func runVersion(cmd *cobra.Command, args []string) error {
	fmt.Fprintf(cmd.OutOrStdout(), "Titus v%s (Go port of NoseyParker)\n", version)
	return nil
}
