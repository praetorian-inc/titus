package main

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
)

var (
	rulesPath    string
	outputFormat string
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage detection rules",
	Long:  "Commands for listing and inspecting detection rules",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available rules",
	Long:  "Display all available detection rules with their IDs and names",
	RunE:  runRulesList,
}

func init() {
	rulesCmd.AddCommand(rulesListCmd)
	rulesListCmd.Flags().StringVar(&rulesPath, "rules", "", "Path to custom rules file or directory")
	rulesListCmd.Flags().StringVar(&outputFormat, "format", "table", "Output format: table, json")
}

func runRulesList(cmd *cobra.Command, args []string) error {
	loader := rule.NewLoader()

	var rules []*types.Rule
	var err error

	// Load rules (builtin or custom)
	if rulesPath != "" {
		// Custom rules from file
		r, loadErr := loader.LoadRuleFile(rulesPath)
		if loadErr != nil {
			return fmt.Errorf("loading rules from %s: %w", rulesPath, loadErr)
		}
		rules = []*types.Rule{r}
	} else {
		// Builtin rules
		rules, err = loader.LoadBuiltinRules()
		if err != nil {
			return fmt.Errorf("loading builtin rules: %w", err)
		}
	}

	// Output based on format
	switch outputFormat {
	case "json":
		return outputRulesJSON(cmd, rules)
	case "table":
		return outputRulesTable(cmd, rules)
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
}

// =============================================================================
// HELPERS
// =============================================================================

func outputRulesJSON(cmd *cobra.Command, rules []*types.Rule) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(rules)
}

func outputRulesTable(cmd *cobra.Command, rules []*types.Rule) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "ID\tName\tCategories\n")
	fmt.Fprintf(w, "--\t----\t----------\n")

	for _, r := range rules {
		categories := ""
		if len(r.Categories) > 0 {
			categories = r.Categories[0]
			if len(r.Categories) > 1 {
				categories += fmt.Sprintf(" (+%d)", len(r.Categories)-1)
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.ID, r.Name, categories)
	}

	return nil
}
