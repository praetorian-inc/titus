package main

import (
	"encoding/json"
	"fmt"
	"sort"

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

	// Validation Summary (if any matches have validation)
	validCount := 0
	invalidCount := 0
	undeterminedCount := 0
	for _, m := range matches {
		if m.ValidationResult != nil {
			switch m.ValidationResult.Status {
			case types.StatusValid:
				validCount++
			case types.StatusInvalid:
				invalidCount++
			default:
				undeterminedCount++
			}
		}
	}
	if validCount > 0 || invalidCount > 0 || undeterminedCount > 0 {
		fmt.Fprintf(out, "Validation Summary:\n")
		fmt.Fprintf(out, "  Valid: %d\n", validCount)
		fmt.Fprintf(out, "  Invalid: %d\n", invalidCount)
		fmt.Fprintf(out, "  Undetermined: %d\n", undeterminedCount)
		fmt.Fprintf(out, "\n")
	}

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

	// Build content-based finding-to-match map for validation lookup
	matchesByFinding := make(map[string][]*types.Match)
	for _, m := range matches {
		r, ok := ruleMap[m.RuleID]
		if ok {
			// Use content-based finding ID when rule is available
			findingID := types.ComputeFindingID(r.StructuralID, m.Groups)
			matchesByFinding[findingID] = append(matchesByFinding[findingID], m)
		}
	}

	// Fallback: if no rule found, try to match findings and matches by RuleID and Groups
	// This handles cases where rules aren't in builtin rules
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

			// Find match for this finding using content-based ID
			var matchForFinding *types.Match
			if matchList := matchesByFinding[f.ID]; len(matchList) > 0 {
				matchForFinding = matchList[0] // use first match
			}

			// Show validation status if available
			if matchForFinding != nil && matchForFinding.ValidationResult != nil {
				fmt.Fprintf(out, "     Validation: [%s] %s\n",
					matchForFinding.ValidationResult.Status,
					matchForFinding.ValidationResult.Message)
			}

			// Show snippet
			if matchForFinding != nil && len(matchForFinding.Snippet.Matching) > 0 {
				fmt.Fprintf(out, "     Snippet: %s\n", matchForFinding.Snippet.Matching)
			}
		}
		fmt.Fprintf(out, "\n")
	}

	return nil
}
