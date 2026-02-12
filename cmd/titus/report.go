package main

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/titus/pkg/rule"
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

	// Load rules for finding ID computation
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}
	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Output based on format
	switch reportFormat {
	case "json":
		return outputReportJSON(cmd, findings, matches, ruleMap)
	case "human":
		return outputReportHuman(cmd, findings, matches, reportDatastore, ruleMap)
	case "sarif":
		return fmt.Errorf("SARIF output not yet implemented")
	default:
		return fmt.Errorf("unknown output format: %s", reportFormat)
	}
}

// =============================================================================
// HELPERS
// =============================================================================

func outputReportJSON(cmd *cobra.Command, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) error {
	// Group matches by finding ID using content-based computation
	matchesByFinding := make(map[string][]*types.Match)
	for _, m := range matches {
		// Compute content-based finding ID (same as scan.go)
		r, ok := ruleMap[m.RuleID]
		if ok {
			findingID := types.ComputeFindingID(r.StructuralID, m.Groups)
			matchesByFinding[findingID] = append(matchesByFinding[findingID], m)
		}
	}

	// Fallback: if no rule found, try to match findings and matches by RuleID and Groups
	for _, f := range findings {
		if _, exists := matchesByFinding[f.ID]; !exists {
			// No matches found yet for this finding, try RuleID + Groups match
			for _, m := range matches {
				if m.RuleID == f.RuleID && len(m.Groups) == len(f.Groups) {
					// Check if groups match
					groupsMatch := true
					for i := range m.Groups {
						if string(m.Groups[i]) != string(f.Groups[i]) {
							groupsMatch = false
							break
						}
					}
					if groupsMatch {
						matchesByFinding[f.ID] = append(matchesByFinding[f.ID], m)
					}
				}
			}
		}
	}

	// Attach matches to their findings
	for _, f := range findings {
		f.Matches = matchesByFinding[f.ID]
	}

	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(findings)
}

func outputReportHuman(cmd *cobra.Command, findings []*types.Finding, matches []*types.Match, datastorePath string, ruleMap map[string]*types.Rule) error {
	out := cmd.OutOrStdout()
	s, err := store.New(store.Config{Path: datastorePath})
	if err != nil {
		return fmt.Errorf("opening datastore for provenance: %w", err)
	}
	defer s.Close()

	// Build content-based finding-to-match map
	matchesByFinding := make(map[string][]*types.Match)
	for _, m := range matches {
		r, ok := ruleMap[m.RuleID]
		if ok {
			findingID := types.ComputeFindingID(r.StructuralID, m.Groups)
			matchesByFinding[findingID] = append(matchesByFinding[findingID], m)
		}
	}

	// Fallback for rules not in builtin rules
	for _, f := range findings {
		if _, exists := matchesByFinding[f.ID]; !exists {
			for _, m := range matches {
				if m.RuleID == f.RuleID && len(m.Groups) == len(f.Groups) {
					groupsMatch := true
					for i := range m.Groups {
						if string(m.Groups[i]) != string(f.Groups[i]) {
							groupsMatch = false
							break
						}
					}
					if groupsMatch {
						matchesByFinding[f.ID] = append(matchesByFinding[f.ID], m)
					}
				}
			}
		}
	}

	totalFindings := len(findings)

	// Output each finding in noseyparker format
	for i, f := range findings {
		// Finding header
		fmt.Fprintf(out, "Finding %d/%d (id %s)\n", i+1, totalFindings, f.ID)

		// Rule name
		ruleName := f.RuleID
		if r, ok := ruleMap[f.RuleID]; ok {
			ruleName = r.Name
		}
		fmt.Fprintf(out, "Rule: %s\n", ruleName)

		// Capture groups
		for j, group := range f.Groups {
			fmt.Fprintf(out, "Group %d: %s\n", j+1, string(group))
		}

		// Matches for this finding
		findingMatches := matchesByFinding[f.ID]
		if len(findingMatches) > 3 {
			fmt.Fprintf(out, "Showing 3/%d matches:\n", len(findingMatches))
			findingMatches = findingMatches[:3]
		}

		for k, match := range findingMatches {
			fmt.Fprintf(out, "\n    Match %d/%d (id %s)\n", k+1, len(matchesByFinding[f.ID]), match.StructuralID)

			// File path from provenance
			prov, err := s.GetProvenance(match.BlobID)
			if err == nil && prov != nil {
				fmt.Fprintf(out, "    File: %s\n", prov.Path())
			}

			// Blob info
			fmt.Fprintf(out, "    Blob: %s\n", match.BlobID.Hex())

			// Line info
			if match.Location.Source.Start.Line > 0 {
				fmt.Fprintf(out, "    Lines: %d:%d-%d:%d\n",
					match.Location.Source.Start.Line, match.Location.Source.Start.Column,
					match.Location.Source.End.Line, match.Location.Source.End.Column)
			}

			// Context snippet
			if len(match.Snippet.Matching) > 0 {
				snippet := string(match.Snippet.Matching)
				if len(snippet) > 100 {
					snippet = snippet[:100] + "..."
				}
				fmt.Fprintf(out, "\n        %s\n", snippet)
			}
		}

		fmt.Fprintf(out, "\n\n")
	}

	return nil
}
