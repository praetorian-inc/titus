package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
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
	scanMaxFileSize   int64
	scanIncludeHidden bool
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
		Rules: rules,
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

	// Scan
	ctx := context.Background()
	matchCount := 0
	findingCount := 0

	err = enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
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

	// Output results (to stderr when using json format to keep stdout pure JSON)
	if scanOutputFormat == "json" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Scan complete: %d matches, %d findings\n", matchCount, findingCount)
		fmt.Fprintf(cmd.ErrOrStderr(), "Results stored in: %s\n", scanOutputPath)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Scan complete: %d matches, %d findings\n", matchCount, findingCount)
		fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", scanOutputPath)
	}

	// Get and output findings
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
	case "sarif":
		// SARIF format would be implemented here
		return fmt.Errorf("SARIF output not yet implemented")
	default:
		return fmt.Errorf("unknown output format: %s", scanOutputFormat)
	}
}
