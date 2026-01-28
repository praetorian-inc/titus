package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
)

var (
	reportDatastore string
	reportFormat    string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report from scan results",
	Long:  "Read findings from a datastore and output a summary report",
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportDatastore, "datastore", "titus.db", "Path to datastore file")
	reportCmd.Flags().StringVar(&reportFormat, "format", "human", "Output format: human, json, sarif")
}

func runReport(cmd *cobra.Command, args []string) error {
	// Open store
	s, err := store.New(store.Config{
		Path: reportDatastore,
	})
	if err != nil {
		return fmt.Errorf("opening datastore: %w", err)
	}
	defer s.Close()

	// Get findings
	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}

	// Get all matches for additional context
	matches, err := s.GetAllMatches()
	if err != nil {
		return fmt.Errorf("retrieving matches: %w", err)
	}

	// Output based on format
	switch reportFormat {
	case "json":
		return outputReportJSON(cmd, findings)
	case "human":
		return outputReportHuman(cmd, findings, matches, reportDatastore)
	case "sarif":
		return fmt.Errorf("SARIF output not yet implemented")
	default:
		return fmt.Errorf("unknown output format: %s", reportFormat)
	}
}

// =============================================================================
// HELPERS
// =============================================================================

func outputReportJSON(cmd *cobra.Command, findings []*types.Finding) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(findings)
}

func outputReportHuman(cmd *cobra.Command, findings []*types.Finding, matches []*types.Match, datastorePath string) error {
	out := cmd.OutOrStdout()

	// Header
	fmt.Fprintf(out, "=== Titus Report ===\n")
	fmt.Fprintf(out, "Datastore: %s\n", datastorePath)
	fmt.Fprintf(out, "\n")

	// Summary
	fmt.Fprintf(out, "Findings Summary:\n")
	fmt.Fprintf(out, "  Total findings: %d\n", len(findings))

	// Unique secrets (by structural ID)
	uniqueStructuralIDs := make(map[string]bool)
	for _, f := range findings {
		uniqueStructuralIDs[f.ID] = true
	}
	fmt.Fprintf(out, "  Unique secrets: %d (by structural ID)\n", len(uniqueStructuralIDs))

	// Rules matched
	uniqueRules := make(map[string]bool)
	for _, f := range findings {
		uniqueRules[f.RuleID] = true
	}
	fmt.Fprintf(out, "  Rules matched: %d\n", len(uniqueRules))
	fmt.Fprintf(out, "\n")

	// By Rule breakdown
	if len(findings) > 0 {
		fmt.Fprintf(out, "By Rule:\n")

		// Count findings per rule
		ruleCount := make(map[string]int)
		for _, f := range findings {
			ruleCount[f.RuleID]++
		}

		// Sort rules by name for consistent output
		rules := make([]string, 0, len(ruleCount))
		for rule := range ruleCount {
			rules = append(rules, rule)
		}
		sort.Strings(rules)

		// Output each rule with count
		for _, rule := range rules {
			count := ruleCount[rule]
			fmt.Fprintf(out, "  %s: %d findings\n", rule, count)
		}
		fmt.Fprintf(out, "\n")
	}

	// Recent Findings (up to 10)
	if len(findings) > 0 {
		fmt.Fprintf(out, "Recent Findings:\n")
		limit := 10
		if len(findings) < limit {
			limit = len(findings)
		}

		for i := 0; i < limit; i++ {
			f := findings[i]
			fmt.Fprintf(out, "  %d. Rule: %s\n", i+1, f.RuleID)

			// Try to find a match for this finding to show snippet
			var matchForFinding *types.Match
			for _, m := range matches {
				// Match finding by checking if match's structural ID matches finding ID
				// or by checking rule ID
				if m.RuleID == f.RuleID {
					matchForFinding = m
					break
				}
			}

			if matchForFinding != nil && len(matchForFinding.Snippet.Matching) > 0 {
				fmt.Fprintf(out, "     Snippet: %s\n", matchForFinding.Snippet.Matching)
			}
		}
		fmt.Fprintf(out, "\n")
	}

	return nil
}
