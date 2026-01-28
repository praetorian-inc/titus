package main

import (
	"fmt"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/spf13/cobra"
)

var (
	mergeOutput string
)

var mergeCmd = &cobra.Command{
	Use:   "merge <source1.db> <source2.db> [source3.db...]",
	Short: "Merge multiple Titus databases",
	Long: `Merge multiple Titus databases into a single output database.

This is useful for combining results from distributed scans or
merging results from different scan targets.

Deduplication is automatic - duplicate blobs, matches, and findings
are only stored once in the merged database.`,
	Args: cobra.MinimumNArgs(2),
	RunE: runMerge,
}

func init() {
	mergeCmd.Flags().StringVarP(&mergeOutput, "output", "o", "merged.db", "Output database path")
}

func runMerge(cmd *cobra.Command, args []string) error {
	stats, err := store.Merge(store.MergeConfig{
		SourcePaths: args,
		DestPath:    mergeOutput,
	})
	if err != nil {
		return fmt.Errorf("merge failed: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Merge complete:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Sources processed: %d\n", stats.SourcesProcessed)
	fmt.Fprintf(cmd.OutOrStdout(), "  Blobs merged: %d\n", stats.BlobsMerged)
	fmt.Fprintf(cmd.OutOrStdout(), "  Matches merged: %d\n", stats.MatchesMerged)
	fmt.Fprintf(cmd.OutOrStdout(), "  Findings merged: %d\n", stats.FindingsMerged)
	fmt.Fprintf(cmd.OutOrStdout(), "  Provenance merged: %d\n", stats.ProvenanceMerged)
	fmt.Fprintf(cmd.OutOrStdout(), "Output: %s\n", mergeOutput)

	return nil
}
