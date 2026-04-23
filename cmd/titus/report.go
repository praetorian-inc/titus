package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/sarif"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	reportDatastore      string
	reportFormat         string
	reportColor          string
	summaryFormat        string
	reportShowRejected bool
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

var summaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show a summary of findings by rule type",
	Long:  "Display total counts and per-rule breakdown of findings and matches",
	RunE:  runSummary,
}

// summaryResult holds the aggregated summary data for output.
type summaryResult struct {
	TotalFindings int           `json:"total_findings"`
	TotalMatches  int           `json:"total_matches"`
	Rules         []ruleSummary `json:"rules"`
}

// ruleSummary holds per-rule aggregated counts.
type ruleSummary struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Findings int    `json:"findings"`
	Matches  int    `json:"matches"`
}

// aggregateSummary builds per-rule summary stats from findings and their matches.
func aggregateSummary(findings []*types.Finding, matchesByFinding map[string][]*types.Match, ruleMap map[string]*types.Rule) summaryResult {
	type stats struct {
		name     string
		findings int
		matches  int
	}
	statsMap := make(map[string]*stats)

	for _, f := range findings {
		if _, exists := statsMap[f.RuleID]; !exists {
			name := f.RuleID
			if r, ok := ruleMap[f.RuleID]; ok {
				name = r.Name
			}
			statsMap[f.RuleID] = &stats{name: name}
		}
		statsMap[f.RuleID].findings++
		statsMap[f.RuleID].matches += len(matchesByFinding[f.ID])
	}

	// Build sorted slice
	result := summaryResult{}
	for ruleID, s := range statsMap {
		result.Rules = append(result.Rules, ruleSummary{
			RuleID:   ruleID,
			RuleName: s.name,
			Findings: s.findings,
			Matches:  s.matches,
		})
		result.TotalFindings += s.findings
		result.TotalMatches += s.matches
	}

	sort.Slice(result.Rules, func(i, j int) bool {
		if result.Rules[i].Findings != result.Rules[j].Findings {
			return result.Rules[i].Findings > result.Rules[j].Findings
		}
		return result.Rules[i].RuleID < result.Rules[j].RuleID
	})

	return result
}

func outputSummaryHuman(out io.Writer, summary summaryResult, colorEnabled bool) error {
	if summary.TotalFindings == 0 {
		_, _ = fmt.Fprintf(out, "No findings.\n")
		return nil
	}

	s := newStyles(colorEnabled)

	_, _ = fmt.Fprintf(out, "%s %d findings, %d matches\n\n",
		s.heading.Sprint("Total:"), summary.TotalFindings, summary.TotalMatches)

	// Find longest rule name for column width
	maxNameLen := len("Rule")
	for _, r := range summary.Rules {
		if len(r.RuleName) > maxNameLen {
			maxNameLen = len(r.RuleName)
		}
	}

	// Print header
	_, _ = fmt.Fprintf(out, " %s   %s   %s \n",
		s.heading.Sprintf("%-*s", maxNameLen, "Rule"),
		s.heading.Sprint("Findings"),
		s.heading.Sprint("Matches"))

	// Print separator line
	separatorLen := maxNameLen + 3 + 10 + 3 + 8
	_, _ = fmt.Fprintf(out, "%s\n", strings.Repeat("─", separatorLen))

	// Print data rows
	for _, r := range summary.Rules {
		_, _ = fmt.Fprintf(out, " %s   %8d   %7d \n",
			s.ruleName.Sprintf("%-*s", maxNameLen, r.RuleName), r.Findings, r.Matches)
	}

	return nil
}

func outputSummaryJSON(out io.Writer, summary summaryResult) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func init() {
	reportCmd.PersistentFlags().StringVar(&reportDatastore, "datastore", "titus.ds", "Path to datastore directory or file")
	reportCmd.Flags().StringVar(&reportFormat, "format", "human", "Output format: human, json, sarif")
	reportCmd.PersistentFlags().StringVar(&reportColor, "color", "auto", "Color output: auto, always, never")
	reportCmd.PersistentFlags().Lookup("color").NoOptDefVal = "always"
	reportCmd.PersistentFlags().BoolVar(&reportShowRejected, "show-rejected", false, "Include findings marked as rejected via the explore command (hidden by default)")

	reportCmd.AddCommand(summaryCmd)
	summaryCmd.Flags().StringVar(&summaryFormat, "format", "human", "Output format: human, json")
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
	defer func() { _ = s.Close() }()

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

	// Filter out findings with rejected annotations unless --show-rejected is set
	if !reportShowRejected {
		findings, matches, err = filterRejected(s, findings, matches, ruleMap)
		if err != nil {
			return fmt.Errorf("filtering rejected findings: %w", err)
		}
	}

	// Output based on format
	switch reportFormat {
	case "json":
		return outputReportJSON(cmd, s, findings, matches, ruleMap)
	case "human":
		return outputReportHuman(cmd, findings, matches, storePath, ruleMap)
	case "sarif":
		return outputReportSARIF(cmd, s, findings, matches, ruleMap)
	default:
		return fmt.Errorf("unknown output format: %s", reportFormat)
	}
}

func runSummary(cmd *cobra.Command, args []string) error {
	// Determine store path (inherited from parent report command)
	storePath := reportDatastore

	if storePath == ":memory:" {
		return fmt.Errorf("cannot report from in-memory store")
	}

	info, err := os.Stat(storePath)
	if err != nil {
		return fmt.Errorf("datastore not found: %s", storePath)
	}
	if info.IsDir() {
		storePath = filepath.Join(storePath, "datastore.db")
	}

	s, err := store.New(store.Config{
		Path: storePath,
	})
	if err != nil {
		return fmt.Errorf("opening datastore: %w", err)
	}
	defer func() { _ = s.Close() }()

	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}

	matches, err := s.GetAllMatches()
	if err != nil {
		return fmt.Errorf("retrieving matches: %w", err)
	}

	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}
	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Filter out findings with rejected annotations unless --show-rejected is set
	if !reportShowRejected {
		findings, matches, err = filterRejected(s, findings, matches, ruleMap)
		if err != nil {
			return fmt.Errorf("filtering rejected findings: %w", err)
		}
	}

	matchesByFinding := buildFindingMatchMap(findings, matches, ruleMap)
	summary := aggregateSummary(findings, matchesByFinding, ruleMap)

	// Determine color setting (inherited from parent)
	switch reportColor {
	case "always":
		color.NoColor = false
	case "never":
		color.NoColor = true
	default:
		if !term.IsTerminal(int(os.Stdout.Fd())) || os.Getenv("NO_COLOR") != "" {
			color.NoColor = true
		} else {
			color.NoColor = false
		}
	}

	switch summaryFormat {
	case "json":
		return outputSummaryJSON(cmd.OutOrStdout(), summary)
	case "human":
		return outputSummaryHuman(cmd.OutOrStdout(), summary, !color.NoColor)
	default:
		return fmt.Errorf("unknown output format: %s", summaryFormat)
	}
}

// =============================================================================
// HELPERS
// =============================================================================

// filterRejected removes findings that have a "reject" annotation and all
// matches associated with those findings. Returns an error if the annotation
// lookup fails so callers can decide whether to proceed without filtering or
// abort entirely.
func filterRejected(s store.Store, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) ([]*types.Finding, []*types.Match, error) {
	annotations, err := s.GetAnnotationsByType("finding")
	if err != nil {
		return nil, nil, fmt.Errorf("retrieving annotations: %w", err)
	}

	// Determine which finding IDs are rejected
	rejectedFindingIDs := make(map[string]bool)
	for _, f := range findings {
		if annotations[f.ID] == store.StatusReject {
			rejectedFindingIDs[f.ID] = true
		}
	}

	if len(rejectedFindingIDs) == 0 {
		return findings, matches, nil
	}

	// Collect structural IDs of matches that belong to rejected findings
	matchesByFinding := buildFindingMatchMap(findings, matches, ruleMap)
	rejectedMatchIDs := make(map[string]bool)
	for fID := range rejectedFindingIDs {
		for _, m := range matchesByFinding[fID] {
			rejectedMatchIDs[m.StructuralID] = true
		}
	}

	filteredFindings := make([]*types.Finding, 0, len(findings))
	for _, f := range findings {
		if !rejectedFindingIDs[f.ID] {
			filteredFindings = append(filteredFindings, f)
		}
	}

	filteredMatches := make([]*types.Match, 0, len(matches))
	for _, m := range matches {
		if !rejectedMatchIDs[m.StructuralID] {
			filteredMatches = append(filteredMatches, m)
		}
	}

	return filteredFindings, filteredMatches, nil
}

// buildFindingMatchMap groups matches by finding ID using content-based computation.
// It uses structural ID matching with a fallback to RuleID + Groups matching.
func buildFindingMatchMap(findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) map[string][]*types.Match {
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

	return matchesByFinding
}

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

// outputReportSARIF writes findings in SARIF 2.1.0 format with score metadata.
// Each finding's matches are included as SARIF results; score data is embedded
// in result.properties so downstream consumers (GitHub Code Scanning, etc.) can
// use the severity tiers without re-computing them.
func outputReportSARIF(cmd *cobra.Command, s store.Store, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) error {
	report := sarif.NewReport()

	// Add all rules from the rule map
	for _, r := range ruleMap {
		report.AddRule(r)
	}

	// Build finding lookup by ID for score retrieval
	findingByID := make(map[string]*types.Finding, len(findings))
	for _, f := range findings {
		findingByID[f.ID] = f
	}

	// Cache provenance by blob ID to avoid repeated store queries
	provenanceCache := make(map[types.BlobID]string)

	for _, match := range matches {
		filePath, ok := provenanceCache[match.BlobID]
		if !ok {
			prov, err := s.GetProvenance(match.BlobID)
			if err != nil {
				filePath = match.BlobID.Hex()
			} else {
				filePath = prov.Path()
			}
			provenanceCache[match.BlobID] = filePath
		}

		// Look up score from the corresponding finding
		var score *types.Score
		if r, ok := ruleMap[match.RuleID]; ok {
			fid := types.ComputeFindingID(r.StructuralID, match.Groups)
			if f, ok := findingByID[fid]; ok {
				score = f.Score
			}
		}
		report.AddResultWithScore(match, filePath, score)
	}

	jsonBytes, err := report.ToJSON()
	if err != nil {
		return fmt.Errorf("serializing SARIF: %w", err)
	}

	_, err = cmd.OutOrStdout().Write(jsonBytes)
	if err != nil {
		return fmt.Errorf("writing SARIF output: %w", err)
	}

	return nil
}

// jsonMatch is a shadow type for types.Match that adds a file_path field to
// the JSON output without modifying the shared types.Match struct. Embedding
// *types.Match exposes all existing fields; the outer FilePath field takes
// precedence over any same-named field on the embedded struct.
type jsonMatch struct {
	*types.Match
	FilePath string `json:"file_path"`
}

// jsonFinding is a shadow type for types.Finding that replaces the Matches
// slice with []jsonMatch so each match carries a file_path. The json tag
// here must match the marshaled name of types.Finding.Matches; if that
// field ever gains an explicit json tag, update this tag in lockstep or
// the output will contain two "Matches" keys.
type jsonFinding struct {
	*types.Finding
	Matches []jsonMatch `json:"Matches"`
}

func outputReportJSON(cmd *cobra.Command, s store.Store, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) error {
	// Group matches by finding ID using content-based computation.
	matchesByFinding := buildFindingMatchMap(findings, matches, ruleMap)

	// Cache provenance path lookups to avoid redundant store queries.
	provenanceCache := make(map[types.BlobID]string)

	// Build the output slice using the shadow types so we don't mutate
	// the shared types.Finding/types.Match structs.
	out := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		ms := matchesByFinding[f.ID]
		jms := make([]jsonMatch, 0, len(ms))
		for _, m := range ms {
			filePath, ok := provenanceCache[m.BlobID]
			if !ok {
				prov, err := s.GetProvenance(m.BlobID)
				if err != nil {
					filePath = m.BlobID.Hex()
				} else {
					filePath = prov.Path()
				}
				provenanceCache[m.BlobID] = filePath
			}
			jms = append(jms, jsonMatch{Match: m, FilePath: filePath})
		}
		out = append(out, jsonFinding{Finding: f, Matches: jms})
	}

	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
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
	defer func() { _ = store.Close() }()

	// Build content-based finding-to-match map
	matchesByFinding := buildFindingMatchMap(findings, matches, ruleMap)

	totalFindings := len(findings)

	// Output each finding in noseyparker format with colors
	for i, f := range findings {
		// Finding header - "Finding N/M" in findingHeading style, "(id xyz)" with ID in id style
		_, _ = fmt.Fprintf(out, "%s (%s %s)\n",
			s.findingHeading.Sprintf("Finding %d/%d", i+1, totalFindings),
			s.heading.Sprint("id"),
			s.id.Sprint(f.ID))

		// Score badge — printed immediately after the finding header when Score is set.
		if f.Score != nil {
			severityColor := s.heading // default to bold for unknown tiers
			switch f.Score.SuggestedSeverity {
			case "critical":
				severityColor = color.New(color.FgHiRed, color.Bold)
			case "high":
				severityColor = color.New(color.FgHiYellow, color.Bold)
			case "medium":
				severityColor = color.New(color.FgHiBlue)
			case "low", "info":
				severityColor = color.New(color.Faint)
			}
			if color.NoColor {
				severityColor.DisableColor()
			}
			_, _ = fmt.Fprintf(out, "%s %d/100 (%s)\n",
				s.heading.Sprint("Score:"),
				f.Score.Final,
				severityColor.Sprint(f.Score.SuggestedSeverity))
		}

		// Rule name - "Rule:" in heading style, rule name in ruleName style
		ruleName := f.RuleID
		if r, ok := ruleMap[f.RuleID]; ok {
			ruleName = r.Name
		}
		_, _ = fmt.Fprintf(out, "%s %s\n", s.heading.Sprint("Rule:"), s.ruleName.Sprint(ruleName))

		// Capture groups - "Group N:" in heading style, value in match style
		for j, group := range f.Groups {
			_, _ = fmt.Fprintf(out, "%s %s\n",
				s.heading.Sprintf("Group %d:", j+1),
				s.match.Sprint(string(group)))
		}

		// Matches for this finding
		findingMatches := matchesByFinding[f.ID]
		if len(findingMatches) > 3 {
			_, _ = fmt.Fprintf(out, "Showing 3/%d matches:\n", len(findingMatches))
			findingMatches = findingMatches[:3]
		}

		for k, match := range findingMatches {
			// Match header - "Match N/M" in heading style, "(id xyz)" with ID in id style
			_, _ = fmt.Fprintf(out, "\n    %s (%s %s)\n",
				s.heading.Sprintf("Match %d/%d", k+1, len(matchesByFinding[f.ID])),
				s.heading.Sprint("id"),
				s.id.Sprint(match.StructuralID))

			// File path from provenance - "File:" in heading style, path in metadata style
			prov, err := store.GetProvenance(match.BlobID)
			if err == nil && prov != nil {
				label := "File:"
				switch prov.Kind() {
				case "archive", "extended":
					label = "Source:"
				}
				_, _ = fmt.Fprintf(out, "    %s %s\n",
					s.heading.Sprint(label),
					s.metadata.Sprint(prov.Path()))
				if gp, ok := prov.(types.GitProvenance); ok && gp.Commit != nil && !gp.Commit.CommitterTimestamp.IsZero() {
					_, _ = fmt.Fprintf(out, "    %s %s\n",
						s.heading.Sprint("Date:"),
						s.metadata.Sprint(gp.Commit.CommitterTimestamp.Format("2006-01-02 15:04:05")))
				}
			}

			// Blob info - "Blob:" in heading style, ID in metadata style
			_, _ = fmt.Fprintf(out, "    %s %s\n",
				s.heading.Sprint("Blob:"),
				s.metadata.Sprint(match.BlobID.Hex()))

			// Line info - "Lines:" in heading style
			if match.Location.Source.Start.Line > 0 {
				_, _ = fmt.Fprintf(out, "    %s %d:%d-%d:%d\n",
					s.heading.Sprint("Lines:"),
					match.Location.Source.Start.Line, match.Location.Source.Start.Column,
					match.Location.Source.End.Line, match.Location.Source.End.Column)
			}

			// Context snippet with colored matching portion
			parts := formatSnippetWithParts(match.Snippet.Before, match.Snippet.Matching, match.Snippet.After, 500)
			if parts.prefix != "" || parts.before != "" || parts.matching != "" || parts.after != "" || parts.suffix != "" {
				_, _ = fmt.Fprintf(out, "\n        %s%s%s%s%s\n",
					parts.prefix,
					parts.before,
					s.match.Sprint(parts.matching),
					parts.after,
					parts.suffix)
			}
		}

		_, _ = fmt.Fprintf(out, "\n\n")
	}

	return nil
}
