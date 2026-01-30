package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/sarif"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
	"github.com/spf13/cobra"
)

var (
	scanRulesPath     string
	scanRulesInclude  string
	scanRulesExclude  string
	scanOutputPath    string
	scanOutputFormat  string
	scanGit           bool
	scanMaxFileSize   int64
	scanIncludeHidden bool
	scanContextLines  int
	scanIncremental     bool
	scanValidate        bool
	scanValidateWorkers int
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
	scanCmd.Flags().Int64Var(&scanMaxFileSize, "max-file-size", 10*1024*1024, "Maximum file size to scan (bytes)")
	scanCmd.Flags().BoolVar(&scanIncludeHidden, "include-hidden", false, "Include hidden files and directories")
	scanCmd.Flags().IntVar(&scanContextLines, "context-lines", 3, "Lines of context before/after matches (0 to disable)")
	scanCmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Skip already-scanned blobs")
	scanCmd.Flags().BoolVar(&scanValidate, "validate", false, "validate detected secrets against their source APIs")
	scanCmd.Flags().IntVar(&scanValidateWorkers, "validate-workers", 4, "number of concurrent validation workers")
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Validate target exists
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("target does not exist: %s", target)
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

	// Initialize validation engine (nil if validation disabled)
	validationEngine := initValidationEngine()

	// Create enumerator
	enumerator, err := createEnumerator(target, scanGit)
	if err != nil {
		return fmt.Errorf("creating enumerator: %w", err)
	}

	// Scan
	ctx := context.Background()
	matchCount := 0
	findingCount := 0
	skippedCount := 0

	err = enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
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

		// Validate matches if enabled
		validateMatches(ctx, validationEngine, matches)

		// Store matches and findings
		for _, match := range matches {
			matchCount++

			if err := s.AddMatch(match); err != nil {
				return fmt.Errorf("storing match: %w", err)
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

// Output results (to stderr when using json/sarif format to keep stdout pure JSON)
	if scanOutputFormat == "json" || scanOutputFormat == "sarif" {
		if scanIncremental {
			fmt.Fprintf(cmd.ErrOrStderr(), "Scan complete: %d matches, %d findings (%d blobs skipped)\n", matchCount, findingCount, skippedCount)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Scan complete: %d matches, %d findings\n", matchCount, findingCount)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Results stored in: %s\n", scanOutputPath)
	} else {
		if scanIncremental {
			fmt.Fprintf(cmd.OutOrStdout(), "Scan complete: %d matches, %d findings (%d blobs skipped)\n", matchCount, findingCount, skippedCount)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Scan complete: %d matches, %d findings\n", matchCount, findingCount)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", scanOutputPath)
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

	// Human format outputs findings (deduplicated)
	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}
	return outputFindings(cmd, findings)
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

// initValidationEngine creates the validation engine if validation is enabled.
func initValidationEngine() *validator.Engine {
	if !scanValidate {
		return nil
	}

	var validators []validator.Validator

	// Add AWS validator
	validators = append(validators, validator.NewAWSValidator())

	// Add embedded YAML validators
	embedded, err := validator.LoadEmbeddedValidators()
	if err != nil {
		// Log warning but continue
		fmt.Fprintf(os.Stderr, "warning: failed to load embedded validators: %v\n", err)
	} else {
		validators = append(validators, embedded...)
	}

	return validator.NewEngine(scanValidateWorkers, validators...)
}

// validateMatches validates matches using the validation engine.
func validateMatches(ctx context.Context, engine *validator.Engine, matches []*types.Match) {
	if engine == nil || len(matches) == 0 {
		return
	}

	// Submit all matches for async validation
	results := make([]<-chan *types.ValidationResult, len(matches))
	for i := range matches {
		results[i] = engine.ValidateAsync(ctx, matches[i])
	}

	// Wait for all validations and attach results
	for i, ch := range results {
		result := <-ch
		matches[i].ValidationResult = result
	}
}
