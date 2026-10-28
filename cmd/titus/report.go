package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

var (
	reportDatastore    string
	reportFormat       string
	reportColor        string
	summaryFormat      string
	reportShowRejected bool

	// Selector flag values, bound separately for report and report summary so
	// the two commands never share state.
	reportRepos, reportNamespaces, reportPaths    []string
	summaryRepos, summaryNamespaces, summaryPaths []string
)

// selectorHelp describes the selector flags shared by report and report
// summary. It is appended to both commands' Long text.
const selectorHelp = `

Selecting by source:
  --repo, --namespace and --path restrict the report to the recorded
  locations they select. Each flag may be repeated, and a location selected by
  any value of any flag is kept (union). A finding or match with no selected
  location is left out, and the summary counts only what is kept.

  --repo X selects locations whose repository equals X. X may be written with
  the host (github.com/acme/api), without it (acme/api), or, for a local
  scan, as its recorded absolute folder (/work/a/api).
  --namespace X selects locations whose repository sits under X, matched by
  whole path segments: acme/team selects acme/team/api but not
  acme/team-other/api. X takes the same forms as for --repo.
  --path X selects locations whose recorded path or absolute path equals X.
  A comma is part of a path, so it is never split. An absolute folder is a
  --repo and --namespace form, not a --path form.

  Remaining limitation: a location marked (host not recorded) cannot be tied
  to one host, so a host-qualified --repo or --namespace value may also select
  it. It is matched by dropping the first segment of the value. Scan the
  source again to record its host.

  After a selected report, a note counts the (host not recorded) locations
  that no --repo or --namespace value selected, and another states that
  nothing matched when the selection leaves no findings. Run
  'titus report sources' to list the values that select.`

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
// enabled=false is what --color=never and the NO_COLOR env var resolve to
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
	Long:  "Read findings from a datastore and output a summary report." + selectorHelp,
	RunE:  runReport,
}

var summaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show a summary of findings by rule type",
	Long:  "Display total counts and per-rule breakdown of findings and matches." + selectorHelp,
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

	addSelectorFlags(reportCmd.Flags(), &reportRepos, &reportNamespaces, &reportPaths)
	addSelectorFlags(summaryCmd.Flags(), &summaryRepos, &summaryNamespaces, &summaryPaths)
}

// addSelectorFlags registers the repeatable source selector flags as local
// flags. StringArray, not StringSlice: a comma is a legal path character.
func addSelectorFlags(fs *pflag.FlagSet, repos, namespaces, paths *[]string) {
	fs.StringArrayVar(repos, selectorFlagRepo, nil, "Only locations of this repository, with or without host (repeatable)")
	fs.StringArrayVar(namespaces, selectorFlagNamespace, nil, "Only locations under this namespace, matched by whole path segments (repeatable)")
	fs.StringArrayVar(paths, selectorFlagPath, nil, "Only locations with this recorded path or absolute path (repeatable)")
}

// openReportStore opens the datastore a report command reads. A directory is
// the datastore directory format; the database lives inside it.
func openReportStore(path string) (store.Store, error) {
	if path == ":memory:" {
		return nil, fmt.Errorf("cannot report from in-memory store")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("datastore not found: %s", path)
	}
	if info.IsDir() {
		path = filepath.Join(path, "datastore.db")
	}

	s, err := store.New(store.Config{Path: path})
	if err != nil {
		return nil, fmt.Errorf("opening datastore: %w", err)
	}
	return s, nil
}

// loadReportScope reads the findings and matches a report covers, with the
// rule map, dropping rejected findings unless --show-rejected is set.
func loadReportScope(s store.Store) ([]*types.Finding, []*types.Match, map[string]*types.Rule, error) {
	findings, err := s.GetFindings()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("retrieving findings: %w", err)
	}

	matches, err := s.GetAllMatches()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("retrieving matches: %w", err)
	}

	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading rules: %w", err)
	}
	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	if !reportShowRejected {
		findings, matches, err = filterRejected(s, findings, matches, ruleMap)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("filtering rejected findings: %w", err)
		}
	}
	return findings, matches, ruleMap, nil
}

// resolveColor applies the --color flag to the global color setting and
// reports whether color is enabled. auto enables color only on a terminal
// with NO_COLOR unset.
func resolveColor() bool {
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
	return !color.NoColor
}

func runReport(cmd *cobra.Command, args []string) error {
	// Validate the selectors before the datastore is opened: an invalid one
	// exits non-zero with no report body and never falls back to unfiltered.
	sel, err := newReportSelector(reportRepos, reportNamespaces, reportPaths)
	if err != nil {
		return err
	}

	s, err := openReportStore(reportDatastore)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	findings, matches, ruleMap, err := loadReportScope(s)
	if err != nil {
		return err
	}

	rs, findings, matches, unselectedHNR, err := applySelection(s, sel, findings, matches, ruleMap)
	if err != nil {
		return fmt.Errorf("selecting locations: %w", err)
	}
	notices := selectionNotices(sel, unselectedHNR, len(findings))

	// Output based on format
	switch reportFormat {
	case "json":
		err = outputReportJSON(cmd, rs, findings, matches, ruleMap)
	case "human":
		err = outputReportHuman(cmd, rs, findings, matches, ruleMap)
	case "sarif":
		err = outputReportSARIF(cmd, rs, findings, matches, ruleMap)
	default:
		return fmt.Errorf("unknown output format: %s", reportFormat)
	}
	if err != nil {
		return err
	}
	writeSelectionNotices(cmd, reportFormat == "human", notices)
	return nil
}

func runSummary(cmd *cobra.Command, args []string) error {
	// Validate the selectors before the datastore is opened.
	sel, err := newReportSelector(summaryRepos, summaryNamespaces, summaryPaths)
	if err != nil {
		return err
	}

	// The datastore path and --color are inherited from the parent report command.
	s, err := openReportStore(reportDatastore)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	findings, matches, ruleMap, err := loadReportScope(s)
	if err != nil {
		return err
	}

	// The summary reads only counts, never locations, so the returned store is
	// not needed; the counts come from the retained findings and matches.
	_, findings, matches, unselectedHNR, err := applySelection(s, sel, findings, matches, ruleMap)
	if err != nil {
		return fmt.Errorf("selecting locations: %w", err)
	}
	notices := selectionNotices(sel, unselectedHNR, len(findings))

	matchesByFinding := buildFindingMatchMap(findings, matches, ruleMap)
	summary := aggregateSummary(findings, matchesByFinding, ruleMap)

	colorEnabled := resolveColor()

	switch summaryFormat {
	case "json":
		err = outputSummaryJSON(cmd.OutOrStdout(), summary)
	case "human":
		err = outputSummaryHuman(cmd.OutOrStdout(), summary, colorEnabled)
	default:
		return fmt.Errorf("unknown output format: %s", summaryFormat)
	}
	if err != nil {
		return err
	}
	writeSelectionNotices(cmd, summaryFormat == "human", notices)
	return nil
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
//
// Mirrored by pkg/explore.groupMatchesByFinding; keep the two in sync.
// (cmd/titus is package main and cannot be imported, so the logic is duplicated.)
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

// sanitizeSnippetText makes raw scanned content safe for a terminal. It keeps
// '\n' (CRLF included) and '\t' verbatim so code stays readable, and applies
// types.SanitizeDisplay to the text between them, which escapes ESC sequences
// and other control bytes while leaving printable Unicode unchanged.
func sanitizeSnippetText(s string) string {
	// A CRLF line ending is a newline; only a lone \r is escaped.
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	b.Grow(len(s))
	for {
		i := strings.IndexAny(s, "\n\t")
		if i < 0 {
			b.WriteString(types.SanitizeDisplay(s))
			return b.String()
		}
		b.WriteString(types.SanitizeDisplay(s[:i]))
		b.WriteByte(s[i])
		s = s[i+1:]
	}
}

// trimSplitCR drops the \r that ends part when next starts with \n: a CRLF
// line ending split across two snippet parts, which is a newline and not a
// stray carriage return.
func trimSplitCR(part, next string) string {
	if strings.HasSuffix(part, "\r") && strings.HasPrefix(next, "\n") {
		return part[:len(part)-1]
	}
	return part
}

// sanitized returns p with its content parts made safe for a terminal.
func (p snippetParts) sanitized() snippetParts {
	p.before = trimSplitCR(p.before, p.matching+p.after)
	p.matching = trimSplitCR(p.matching, p.after)
	p.before = sanitizeSnippetText(p.before)
	p.matching = sanitizeSnippetText(p.matching)
	p.after = sanitizeSnippetText(p.after)
	return p
}

// formatSnippetWithParts separates snippet into parts for colored output.
// Truncation works on the raw bytes; each content part is sanitized for
// terminal display afterwards.
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
		}.sanitized()
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
		}.sanitized()
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

	return parts.sanitized()
}

// outputReportSARIF writes findings in SARIF 2.1.0 format with score metadata,
// one result per location of each match's blob. Score data is embedded in
// result.properties so downstream consumers (GitHub Code Scanning, etc.) can
// use the severity tiers without re-computing them.
func outputReportSARIF(cmd *cobra.Command, s store.Store, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) error {
	rules := slices.SortedFunc(maps.Values(ruleMap), func(a, b *types.Rule) int {
		return cmp.Compare(a.ID, b.ID)
	})

	findingByID := make(map[string]*types.Finding, len(findings))
	for _, f := range findings {
		findingByID[f.ID] = f
	}
	scoreFor := func(m *types.Match) *types.Score {
		r, ok := ruleMap[m.RuleID]
		if !ok {
			return nil
		}
		if f, ok := findingByID[types.ComputeFindingID(r.StructuralID, m.Groups)]; ok {
			return f.Score
		}
		return nil
	}
	return writeSARIF(cmd.OutOrStdout(), s, rules, matches, scoreFor)
}

// jsonMatch is a shadow type for types.Match that adds file_path and
// locations to the JSON output without modifying the shared types.Match
// struct. Embedding *types.Match exposes all existing fields; the outer fields
// take precedence over any same-named field on the embedded struct. file_path
// is the first location's path (kept for existing consumers); locations lists
// every location and is never null.
type jsonMatch struct {
	*types.Match
	FilePath  string         `json:"file_path"`
	Locations []jsonLocation `json:"locations"`
	// LocationsTruncated marks a blob with more locations than were recorded.
	LocationsTruncated bool `json:"locations_truncated,omitempty"`
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

	// Cache location lookups per blob to avoid redundant store queries.
	locationCache := make(map[types.BlobID]blobLocations)

	// Build the output slice using the shadow types so we don't mutate
	// the shared types.Finding/types.Match structs.
	out := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		ms := matchesByFinding[f.ID]
		jms := make([]jsonMatch, 0, len(ms))
		for _, m := range ms {
			locs, ok := locationCache[m.BlobID]
			if !ok {
				var err error
				if locs, err = loadBlobLocations(s, m); err != nil {
					return err
				}
				locationCache[m.BlobID] = locs
			}
			filePath := m.BlobID.Hex()
			if len(locs.occs) > 0 {
				filePath = locs.occs[0].Path
			}
			jms = append(jms, jsonMatch{
				Match:              m,
				FilePath:           filePath,
				Locations:          toJSONLocations(m, locs.occs),
				LocationsTruncated: locs.truncated,
			})
		}
		out = append(out, jsonFinding{Finding: f, Matches: jms})
	}

	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

// fullMatches is how many matches of a finding the human report prints in
// full; later matches print only their location lines.
const fullMatches = 3

// outputReportHuman writes findings in NoseyParker-style text. The first three
// matches of a finding print in full (header, blob, snippet, locations); every
// further match prints only its location lines. Every location of every match
// is printed, one line each, through writeLocationLines.
func outputReportHuman(cmd *cobra.Command, s store.Store, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule) error {
	out := cmd.OutOrStdout()

	// Determine if colors should be enabled based on --color flag
	st := newStyles(resolveColor())

	// Build content-based finding-to-match map
	matchesByFinding := buildFindingMatchMap(findings, matches, ruleMap)

	// Cache location lookups per blob to avoid redundant store queries.
	locationCache := make(map[types.BlobID]blobLocations)

	totalFindings := len(findings)

	// Output each finding in noseyparker format with colors
	for i, f := range findings {
		// Finding header - "Finding N/M" in findingHeading style, "(id xyz)" with ID in id style
		_, _ = fmt.Fprintf(out, "%s (%s %s)\n",
			st.findingHeading.Sprintf("Finding %d/%d", i+1, totalFindings),
			st.heading.Sprint("id"),
			st.id.Sprint(f.ID))

		// Score badge — printed immediately after the finding header when Score is set.
		if f.Score != nil {
			severityColor := st.heading // default to bold for unknown tiers
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
				st.heading.Sprint("Score:"),
				f.Score.Final,
				severityColor.Sprint(f.Score.SuggestedSeverity))
		}

		if f.Owner != nil {
			ownerStr := f.Owner.User
			if f.Owner.Email != "" && f.Owner.Email != f.Owner.User {
				ownerStr += " (" + f.Owner.Email + ")"
			}
			if f.Owner.AccountID != "" {
				ownerStr += " [" + f.Owner.AccountID + "]"
			}
			_, _ = fmt.Fprintf(out, "%s %s\n",
				st.heading.Sprint("Owner:"),
				st.metadata.Sprint(types.SanitizeDisplay(ownerStr)))
		}

		if len(f.Resources) > 0 {
			_, _ = fmt.Fprintf(out, "%s %s\n",
				st.heading.Sprint("Resources:"),
				st.metadata.Sprint(formatResourceSummary(f.Resources)))
			for _, r := range f.Resources {
				detail := r.Type + ": " + r.Name
				if r.Count > 0 {
					detail = fmt.Sprintf("%s: %d", r.Type, r.Count)
					if r.Name != "" {
						detail += " (" + r.Name + ")"
					}
				}
				if r.Region != "" {
					detail += " [" + r.Region + "]"
				}
				_, _ = fmt.Fprintf(out, "  %s\n", st.metadata.Sprint(types.SanitizeDisplay(detail)))
			}
		}

		// Rule name - "Rule:" in heading style, rule name in ruleName style
		ruleName := f.RuleID
		if r, ok := ruleMap[f.RuleID]; ok {
			ruleName = r.Name
		}
		_, _ = fmt.Fprintf(out, "%s %s\n", st.heading.Sprint("Rule:"), st.ruleName.Sprint(ruleName))

		// Capture groups - "Group N:" in heading style, value in match style
		for j, group := range f.Groups {
			_, _ = fmt.Fprintf(out, "%s %s\n",
				st.heading.Sprintf("Group %d:", j+1),
				st.match.Sprint(sanitizeSnippetText(string(group))))
		}

		// Matches for this finding: the first fullMatches in full, the rest as
		// location lines only. Nothing is truncated.
		findingMatches := matchesByFinding[f.ID]
		for k, match := range findingMatches {
			locs, ok := locationCache[match.BlobID]
			if !ok {
				var err error
				if locs, err = loadBlobLocations(s, match); err != nil {
					return err
				}
				locationCache[match.BlobID] = locs
			}
			line := match.Location.Source.Start.Line
			if k >= fullMatches {
				writeLocationLines(out, line, locs.occs, st.metadata)
				writeLocationsTruncated(out, locs.truncated, st.metadata)
				continue
			}

			// Match header - "Match N/M" in heading style, "(id xyz)" with ID in id style
			_, _ = fmt.Fprintf(out, "\n    %s (%s %s)\n",
				st.heading.Sprintf("Match %d/%d", k+1, len(findingMatches)),
				st.heading.Sprint("id"),
				st.id.Sprint(match.StructuralID))

			// Blob info - "Blob:" in heading style, ID in metadata style
			_, _ = fmt.Fprintf(out, "    %s %s\n",
				st.heading.Sprint("Blob:"),
				st.metadata.Sprint(match.BlobID.Hex()))

			// Context snippet with colored matching portion
			parts := formatSnippetWithParts(match.Snippet.Before, match.Snippet.Matching, match.Snippet.After, 500)
			if parts.prefix != "" || parts.before != "" || parts.matching != "" || parts.after != "" || parts.suffix != "" {
				_, _ = fmt.Fprintf(out, "\n        %s%s%s%s%s\n\n",
					parts.prefix,
					parts.before,
					st.match.Sprint(parts.matching),
					parts.after,
					parts.suffix)
			}

			writeLocationLines(out, line, locs.occs, st.metadata)
			writeLocationsTruncated(out, locs.truncated, st.metadata)
		}

		_, _ = fmt.Fprintf(out, "\n\n")
	}

	return nil
}

func formatResourceSummary(resources []types.ResourceInfo) string {
	totals := map[string]int{}
	counts := map[string]int{}
	for _, r := range resources {
		if r.Name == "total" && r.Count > 0 {
			totals[r.Type] = r.Count
		} else {
			counts[r.Type]++
		}
	}
	for typ, total := range totals {
		counts[typ] = total
	}
	var parts []string
	for typ, n := range counts {
		parts = append(parts, fmt.Sprintf("%d %s", n, typ))
	}
	sort.Strings(parts)
	// Resource types come from remote APIs; sanitize for terminal display.
	return types.SanitizeDisplay(strings.Join(parts, ", "))
}
