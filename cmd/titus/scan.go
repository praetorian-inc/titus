package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/sarif"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
)

var (
	scanRulesPath     string
	scanRulesInclude  string
	scanRulesExclude  string
	scanOutputPath    string
	scanOutputFormat  string
	scanGit           bool
	scanNoGit         bool
	scanMaxFileSize   int64
	scanIncludeHidden bool
	scanContextLines  int
	scanIncremental   bool
)

var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Scan a target for secrets",
	Long:  "Scan a file, directory, or git repository for secrets using detection rules",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules file or directory")
	scanCmd.Flags().StringVar(&scanRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	scanCmd.Flags().StringVar(&scanRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	scanCmd.Flags().StringVar(&scanOutputPath, "output", "titus.db", "Output database path")
	scanCmd.Flags().StringVar(&scanOutputFormat, "format", "human", "Output format: json, sarif, human")
	scanCmd.Flags().BoolVar(&scanGit, "git", false, "Treat target as git repository (enumerate git history)")
	scanCmd.Flags().BoolVar(&scanNoGit, "no-git", false, "Disable git scanning even if target is a git repository")
	scanCmd.Flags().Int64Var(&scanMaxFileSize, "max-file-size", 10*1024*1024, "Maximum file size to scan (bytes)")
	scanCmd.Flags().BoolVar(&scanIncludeHidden, "include-hidden", false, "Include hidden files and directories")
	scanCmd.Flags().IntVar(&scanContextLines, "context-lines", 3, "Lines of context before/after matches (0 to disable)")
	scanCmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Skip already-scanned blobs")
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Validate target exists
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("target does not exist: %s", target)
	}

	// Auto-detect git repository if --git and --no-git flags are not set
	if !scanGit && !scanNoGit {
		gitDir := filepath.Join(target, ".git")
		if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
			// .git directory exists - this is a git repository
			scanGit = true
			fmt.Fprintf(cmd.OutOrStdout(), "Detected git repository, scanning git history...\n")
		}
	}

	// Load rules
	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	// Create matcher
	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: scanContextLines,
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	// Create store
	s, err := store.New(store.Config{
		Path: scanOutputPath,
	})
	if err != nil {
		return fmt.Errorf("creating store: %w", err)
	}
	defer s.Close()

	// Create enumerator
	enumerator, err := createEnumerator(target, scanGit)
	if err != nil {
		return fmt.Errorf("creating enumerator: %w", err)
	}

	// Track scanning stats
	startTime := time.Now()
	totalBytes := int64(0)
	blobCount := 0

	// Aggregate matches by rule for table output
	type ruleStats struct {
		ruleName     string
		findingCount int
		matchCount   int
	}
	ruleStatsMap := make(map[string]*ruleStats)

	// Initialize rule stats with all loaded rules
	for _, r := range rules {
		ruleStatsMap[r.ID] = &ruleStats{
			ruleName:     r.Name,
			findingCount: 0,
			matchCount:   0,
		}
	}

	// Scan
	ctx := context.Background()
	matchCount := 0
	findingCount := 0
	skippedCount := 0

	err = enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		// Track bytes and blob count
		totalBytes += int64(len(content))
		blobCount++

		// Check for incremental scanning
		if scanIncremental {
			exists, err := s.BlobExists(blobID)
			if err != nil {
				return fmt.Errorf("checking blob: %w", err)
			}
			if exists {
				skippedCount++
				return nil
			}
		}

		// Store blob
		if err := s.AddBlob(blobID, int64(len(content))); err != nil {
			return fmt.Errorf("storing blob: %w", err)
		}

		// Store provenance
		if err := s.AddProvenance(blobID, prov); err != nil {
			return fmt.Errorf("storing provenance: %w", err)
		}

		// Match content
		matches, err := m.MatchWithBlobID(content, blobID)
		if err != nil {
			return fmt.Errorf("matching content: %w", err)
		}

		// Store matches and findings
		for _, match := range matches {
			matchCount++

			if err := s.AddMatch(match); err != nil {
				return fmt.Errorf("storing match: %w", err)
			}

			// Update rule stats
			if stats, ok := ruleStatsMap[match.RuleID]; ok {
				stats.matchCount++
			}

			// Create finding (deduplicated by finding ID)
			// Note: Finding ID is computed from rule structural ID + groups
			// For now, we'll use a simpler approach based on structural ID
			exists, err := s.FindingExists(match.StructuralID)
			if err != nil {
				return fmt.Errorf("checking finding: %w", err)
			}

			if !exists {
				findingCount++

				// Update rule stats for findings
				if stats, ok := ruleStatsMap[match.RuleID]; ok {
					stats.findingCount++
				}

				finding := &types.Finding{
					ID:     match.StructuralID, // Use structural ID as finding ID for now
					RuleID: match.RuleID,
					Groups: match.Groups,
				}
				if err := s.AddFinding(finding); err != nil {
					return fmt.Errorf("storing finding: %w", err)
				}
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	// Calculate scan duration and speed
	duration := time.Since(startTime)
	durationSeconds := duration.Seconds()
	if durationSeconds == 0 {
		durationSeconds = 0.001 // Avoid division by zero
	}
	bytesPerSecond := float64(totalBytes) / durationSeconds
	mibPerSecond := bytesPerSecond / (1024 * 1024)
	totalMiB := float64(totalBytes) / (1024 * 1024)

	// Output results (to stderr when using json/sarif format to keep stdout pure JSON)
	outWriter := cmd.OutOrStdout()
	if scanOutputFormat == "json" || scanOutputFormat == "sarif" {
		outWriter = cmd.ErrOrStderr()
	}

	// Print NoseyParker-style output for human format
	if scanOutputFormat == "human" {
		// Print scan summary
		sourceType := "plain files"
		if scanGit {
			sourceType = "Git repo"
		}
		fmt.Fprintf(outWriter, "Found %.2f MiB from %d blobs from 1 %s\n", totalMiB, blobCount, sourceType)
		fmt.Fprintf(outWriter, "Scanned %.2f MiB from %d blobs in %.0f second (%.2f MiB/s); %d/%d new matches\n\n",
			totalMiB, blobCount, durationSeconds, mibPerSecond, matchCount, matchCount)

		// Print table header
		fmt.Fprintf(outWriter, " %-60s %15s %15s\n", "Rule", "Total Findings", "Total Matches")
		fmt.Fprintf(outWriter, "%s\n", "──────────────────────────────────────────────────────────────────────────────────────────────")

		// Sort rules by match count (descending)
		type ruleSortEntry struct {
			ruleID   string
			ruleName string
			stats    *ruleStats
		}
		var sortedRules []ruleSortEntry
		for ruleID, stats := range ruleStatsMap {
			if stats.matchCount > 0 {
				sortedRules = append(sortedRules, ruleSortEntry{
					ruleID:   ruleID,
					ruleName: stats.ruleName,
					stats:    stats,
				})
			}
		}
		sort.Slice(sortedRules, func(i, j int) bool {
			return sortedRules[i].stats.matchCount > sortedRules[j].stats.matchCount
		})

		// Print table rows
		for _, entry := range sortedRules {
			fmt.Fprintf(outWriter, " %-60s %15d %15d\n",
				entry.ruleName, entry.stats.findingCount, entry.stats.matchCount)
		}

		fmt.Fprintf(outWriter, "\nRun the `report` command next to show finding details.\n")
	} else {
		// For JSON/SARIF, print simple summary
		if scanIncremental {
			fmt.Fprintf(outWriter, "Scan complete: %d matches, %d findings (%d blobs skipped)\n", matchCount, findingCount, skippedCount)
		} else {
			fmt.Fprintf(outWriter, "Scan complete: %d matches, %d findings\n", matchCount, findingCount)
		}
		fmt.Fprintf(outWriter, "Results stored in: %s\n", scanOutputPath)
	}

	// Get results for output
	if scanOutputFormat == "json" {
		// JSON format outputs matches with full snippet data
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	if scanOutputFormat == "sarif" {
		// SARIF format outputs matches with rules
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputSARIF(cmd, s, rules, matches)
	}

	// Human format - already displayed table above
	return nil
}

// =============================================================================
// HELPERS
// =============================================================================

func loadRules(path, include, exclude string) ([]*types.Rule, error) {
	loader := rule.NewLoader()

	var rules []*types.Rule
	var err error

	if path != "" {
		// Custom rules from file
		r, err := loader.LoadRuleFile(path)
		if err != nil {
			return nil, err
		}
		rules = []*types.Rule{r}
	} else {
		// Builtin rules
		rules, err = loader.LoadBuiltinRules()
		if err != nil {
			return nil, err
		}
	}

	// Apply filtering if patterns specified
	if include != "" || exclude != "" {
		config := rule.FilterConfig{
			Include: rule.ParsePatterns(include),
			Exclude: rule.ParsePatterns(exclude),
		}
		rules, err = rule.Filter(rules, config)
		if err != nil {
			return nil, fmt.Errorf("filtering rules: %w", err)
		}
	}

	return rules, nil
}

func createEnumerator(target string, useGit bool) (enum.Enumerator, error) {
	config := enum.Config{
		Root:           target,
		IncludeHidden:  scanIncludeHidden,
		MaxFileSize:    scanMaxFileSize,
		FollowSymlinks: false,
	}

	if useGit {
		return enum.NewGitEnumerator(config), nil
	}

	return enum.NewFilesystemEnumerator(config), nil
}

func outputMatches(cmd *cobra.Command, matches []*types.Match) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(matches)
}

func outputFindings(cmd *cobra.Command, findings []*types.Finding) error {
	switch scanOutputFormat {
	case "json":
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(findings)
	case "human":
		if len(findings) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "\nNo findings.\n")
			return nil
		}

		fmt.Fprintf(cmd.OutOrStdout(), "\nFindings:\n")
		for i, f := range findings {
			fmt.Fprintf(cmd.OutOrStdout(), "%d. Rule: %s\n", i+1, f.RuleID)
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", scanOutputFormat)
	}
}

// outputSARIF outputs matches in SARIF 2.1.0 format
func outputSARIF(cmd *cobra.Command, s store.Store, rules []*types.Rule, matches []*types.Match) error {
	// Create SARIF report
	report := sarif.NewReport()

	// Add all rules
	for _, rule := range rules {
		report.AddRule(rule)
	}

	// Cache provenance by blob ID to avoid repeated queries
	provenanceCache := make(map[types.BlobID]string)

	// Get provenance for each match and add results
	for _, match := range matches {
		// Check cache first
		filePath, ok := provenanceCache[match.BlobID]
		if !ok {
			// Query provenance
			prov, err := s.GetProvenance(match.BlobID)
			if err != nil {
				// If no provenance found, use blob ID as fallback
				filePath = match.BlobID.Hex()
			} else {
				filePath = prov.Path()
			}
			provenanceCache[match.BlobID] = filePath
		}

		report.AddResult(match, filePath)
	}

	// Serialize to JSON
	jsonBytes, err := report.ToJSON()
	if err != nil {
		return fmt.Errorf("serializing SARIF: %w", err)
	}

	// Write to stdout
	_, err = cmd.OutOrStdout().Write(jsonBytes)
	if err != nil {
		return fmt.Errorf("writing SARIF output: %w", err)
	}

	return nil
}
