package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	reportDatastore string
	reportFormat    string
	reportColor     string
)

// styles holds color formatters matching NoseyParker color scheme
type styles struct {
	findingHeading *color.Color
	id             *color.Color
	ruleName       *color.Color
	heading        *color.Color
	match          *color.Color
	metadata       *color.Color
}

// newStyles creates color formatters for report output
// enabled=false respects --no-color flag and NO_COLOR env var
func newStyles(enabled bool) *styles {
	s := &styles{
		findingHeading: color.New(color.Bold, color.FgHiWhite),
		id:             color.New(color.FgHiGreen),
		ruleName:       color.New(color.Bold, color.FgHiBlue),
		heading:        color.New(color.Bold),
		match:          color.New(color.FgYellow),
		metadata:       color.New(color.FgHiBlue),
	}

	if !enabled {
		// Disable colors on all formatters
		s.findingHeading.DisableColor()
		s.id.DisableColor()
		s.ruleName.DisableColor()
		s.heading.DisableColor()
		s.match.DisableColor()
		s.metadata.DisableColor()
	}

	return s
}

// snippetParts holds separated snippet components for colored output
type snippetParts struct {
	prefix   string // "..." if truncated at start
	before   string
	matching string
	after    string
	suffix   string // "..." if truncated at end
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report from scan results",
	Long:  "Read findings from a datastore and output a summary report",
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportDatastore, "datastore", "titus.ds", "Path to datastore directory or file")
	reportCmd.Flags().StringVar(&reportFormat, "format", "human", "Output format: human, json, sarif")
	reportCmd.Flags().StringVar(&reportColor, "color", "auto", "Color output: auto, always, never")
}

func runReport(cmd *cobra.Command, args []string) error {
	// Determine store path
	storePath := reportDatastore

	// Check if it's :memory: (invalid for report)
	if storePath == ":memory:" {
		return fmt.Errorf("cannot report from in-memory store")
	}

	// Check if it's a directory (new datastore format)
	info, err := os.Stat(storePath)
	if err != nil {
		return fmt.Errorf("datastore not found: %s", storePath)
	}
	if info.IsDir() {
		// New datastore directory format - open datastore.db inside
		storePath = filepath.Join(storePath, "datastore.db")
	}

	// Open store
	s, err := store.New(store.Config{
		Path: storePath,
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
		return outputReportHuman(cmd, findings, matches, storePath, ruleMap)
	case "sarif":
		return fmt.Errorf("SARIF output not yet implemented")
	default:
		return fmt.Errorf("unknown output format: %s", reportFormat)
	}
}

// =============================================================================
// HELPERS
// =============================================================================


// formatSnippet combines before/matching/after and truncates to maxLen chars,
// centering the window around the matched text.
func formatSnippet(before, matching, after []byte, maxLen int) string {
	full := string(before) + string(matching) + string(after)
	if len(full) <= maxLen {
		return full
	}

	// Find where the match sits in the combined string
	matchStart := len(before)
	matchEnd := matchStart + len(matching)
	matchLen := len(matching)

	// If match itself exceeds maxLen, show as much of match as possible
	if matchLen >= maxLen {
		result := string(matching[:maxLen-6]) + "..."
		return "..." + result
	}

	// Calculate how much context we can show around the match
	availableContext := maxLen - matchLen - 6 // reserve 6 for potential "..." on each side
	halfContext := availableContext / 2

	// Determine start and end positions
	start := matchStart - halfContext
	end := matchEnd + halfContext

	// Adjust if we're near boundaries
	if start < 0 {
		end -= start // shift end right by the amount we're short on left
		start = 0
	}
	if end > len(full) {
		start -= (end - len(full)) // shift start left by amount we're over on right
		if start < 0 {
			start = 0
		}
		end = len(full)
	}

	// Build result with truncation indicators
	var result string
	if start > 0 {
		result = "..."
	}
	result += full[start:end]
	if end < len(full) {
		result += "..."
	}
	return result
}

// formatSnippetWithParts separates snippet into parts for colored output
func formatSnippetWithParts(before, matching, after []byte, maxLen int) snippetParts {
	full := string(before) + string(matching) + string(after)

	// Short snippet - no truncation needed
	if len(full) <= maxLen {
		return snippetParts{
			prefix:   "",
			before:   string(before),
			matching: string(matching),
			after:    string(after),
			suffix:   "",
		}
	}

	// Find where the match sits in the combined string
	matchStart := len(before)
	matchEnd := matchStart + len(matching)
	matchLen := len(matching)

	// If match itself exceeds maxLen, show truncated match
	if matchLen >= maxLen {
		return snippetParts{
			prefix:   "...",
			before:   "",
			matching: string(matching[:maxLen-6]),
			after:    "",
			suffix:   "...",
		}
	}

	// Calculate how much context we can show around the match
	availableContext := maxLen - matchLen - 6 // reserve 6 for potential "..." on each side
	halfContext := availableContext / 2

	// Determine start and end positions
	start := matchStart - halfContext
	end := matchEnd + halfContext

	// Adjust if we're near boundaries
	if start < 0 {
		end -= start // shift end right by the amount we're short on left
		start = 0
	}
	if end > len(full) {
		start -= (end - len(full)) // shift start left by amount we're over on right
		if start < 0 {
			start = 0
		}
		end = len(full)
	}

	// Build parts with truncation indicators
	parts := snippetParts{}

	if start > 0 {
		parts.prefix = "..."
	}

	// Extract before, matching, and after from the window
	windowStart := start
	windowEnd := end

	// Calculate positions within the window
	windowMatchStart := matchStart - windowStart
	windowMatchEnd := matchEnd - windowStart

	if windowMatchStart > 0 {
		parts.before = full[windowStart:matchStart]
	}
	parts.matching = full[matchStart:matchEnd]
	if windowMatchEnd < windowEnd-windowStart {
		parts.after = full[matchEnd:windowEnd]
	}

	if end < len(full) {
		parts.suffix = "..."
	}

	return parts
}

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

	// Determine if colors should be enabled based on --color flag
	switch reportColor {
	case "always":
		color.NoColor = false
	case "never":
		color.NoColor = true
	default: // "auto"
		// Check if stdout is a TTY and NO_COLOR is not set
		if !term.IsTerminal(int(os.Stdout.Fd())) || os.Getenv("NO_COLOR") != "" {
			color.NoColor = true
		} else {
			color.NoColor = false
		}
	}
	s := newStyles(!color.NoColor)

	// Resolve datastore path (same logic as runReport)
	storePath := datastorePath
	info, err := os.Stat(storePath)
	if err == nil && info.IsDir() {
		storePath = filepath.Join(storePath, "datastore.db")
	}

	store, err := store.New(store.Config{Path: storePath})
	if err != nil {
		return fmt.Errorf("opening datastore for provenance: %w", err)
	}
	defer store.Close()

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

	// Output each finding in noseyparker format with colors
	for i, f := range findings {
		// Finding header - "Finding N/M" in findingHeading style, "(id xyz)" with ID in id style
		fmt.Fprintf(out, "%s (%s %s)\n",
			s.findingHeading.Sprintf("Finding %d/%d", i+1, totalFindings),
			s.heading.Sprint("id"),
			s.id.Sprint(f.ID))

		// Rule name - "Rule:" in heading style, rule name in ruleName style
		ruleName := f.RuleID
		if r, ok := ruleMap[f.RuleID]; ok {
			ruleName = r.Name
		}
		fmt.Fprintf(out, "%s %s\n", s.heading.Sprint("Rule:"), s.ruleName.Sprint(ruleName))

		// Capture groups - "Group N:" in heading style, value in match style
		for j, group := range f.Groups {
			fmt.Fprintf(out, "%s %s\n",
				s.heading.Sprintf("Group %d:", j+1),
				s.match.Sprint(string(group)))
		}

		// Matches for this finding
		findingMatches := matchesByFinding[f.ID]
		if len(findingMatches) > 3 {
			fmt.Fprintf(out, "Showing 3/%d matches:\n", len(findingMatches))
			findingMatches = findingMatches[:3]
		}

		for k, match := range findingMatches {
			// Match header - "Match N/M" in heading style, "(id xyz)" with ID in id style
			fmt.Fprintf(out, "\n    %s (%s %s)\n",
				s.heading.Sprintf("Match %d/%d", k+1, len(matchesByFinding[f.ID])),
				s.heading.Sprint("id"),
				s.id.Sprint(match.StructuralID))

			// File path from provenance - "File:" in heading style, path in metadata style
			prov, err := store.GetProvenance(match.BlobID)
			if err == nil && prov != nil {
				fmt.Fprintf(out, "    %s %s\n",
					s.heading.Sprint("File:"),
					s.metadata.Sprint(prov.Path()))
			}

			// Blob info - "Blob:" in heading style, ID in metadata style
			fmt.Fprintf(out, "    %s %s\n",
				s.heading.Sprint("Blob:"),
				s.metadata.Sprint(match.BlobID.Hex()))

			// Line info - "Lines:" in heading style
			if match.Location.Source.Start.Line > 0 {
				fmt.Fprintf(out, "    %s %d:%d-%d:%d\n",
					s.heading.Sprint("Lines:"),
					match.Location.Source.Start.Line, match.Location.Source.Start.Column,
					match.Location.Source.End.Line, match.Location.Source.End.Column)
			}

			// Context snippet with colored matching portion
			parts := formatSnippetWithParts(match.Snippet.Before, match.Snippet.Matching, match.Snippet.After, 500)
			if parts.prefix != "" || parts.before != "" || parts.matching != "" || parts.after != "" || parts.suffix != "" {
				fmt.Fprintf(out, "\n        %s%s%s%s%s\n",
					parts.prefix,
					parts.before,
					s.match.Sprint(parts.matching),
					parts.after,
					parts.suffix)
			}
		}

		fmt.Fprintf(out, "\n\n")
	}

	return nil
}
