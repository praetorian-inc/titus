package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  "Display the version of Titus (Go port of NoseyParker)",
	RunE:  runVersion,
}

func runVersion(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Titus v%s (Go port of NoseyParker)\n", version)
	fmt.Fprintf(out, "Commit: %s\n", commit)
	fmt.Fprintf(out, "Go version: %s\n", runtime.Version())
	fmt.Fprintf(out, "OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return nil
}
