package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
)

var (
	linearToken        string
	linearOutputPath   string
	linearOutputFormat string
)

var linearCmd = &cobra.Command{
	Use:   "linear",
	Short: "Scan a Linear workspace for secrets",
	Long: `Scan an entire Linear workspace for secrets via the GraphQL API.
Enumerates issues (with comments), documents, and project updates.

Authentication:
  Use --token or LINEAR_TOKEN env var with a Linear API key.
  Create one at: https://linear.app/settings/api

Examples:
  titus linear --token lin_api_xxx
  LINEAR_TOKEN=lin_api_xxx titus linear
  titus linear --token lin_api_xxx --output linear-scan.db --format json`,
	RunE: runLinearScan,
}

func init() {
	linearCmd.Flags().StringVar(&linearToken, "token", "", "Linear API key (or LINEAR_TOKEN env)")
	linearCmd.Flags().StringVar(&linearOutputPath, "output", "titus.db", "Output database path")
	linearCmd.Flags().StringVar(&linearOutputFormat, "format", "human", "Output format: json, human")
	linearCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules file or directory (merged with builtins)")
	linearCmd.Flags().StringVar(&scanRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	linearCmd.Flags().StringVar(&scanRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	linearCmd.Flags().StringVar(&scanRuleset, "ruleset", "default", "Ruleset to use: default, np.assets, np.hashes, all")
	linearCmd.Flags().BoolVar(&scanIncludeNoisy, "include-noisy", false, "Include noisy rules that may produce more false positives")
}

func runLinearScan(cmd *cobra.Command, args []string) error {
	token := linearToken
	if token == "" {
		token = os.Getenv("LINEAR_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("linear API key is required: use --token or LINEAR_TOKEN env var")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewLinearEnumerator(enum.LinearConfig{
		Token:   token,
		Verbose: verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Linear enumerator: %w", err)
	}

	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude, scanRuleset, scanIncludeNoisy)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: 3,
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	s, err := store.New(store.Config{
		Path: linearOutputPath,
	})
	if err != nil {
		return fmt.Errorf("creating store: %w", err)
	}
	defer s.Close()

	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("storing rule: %w", err)
		}
	}

	ctx := context.Background()
	matchCount := 0
	findingCount := 0

	err = enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		if err := s.AddBlob(blobID, int64(len(content))); err != nil {
			return fmt.Errorf("storing blob: %w", err)
		}

		if err := s.AddProvenance(blobID, prov); err != nil {
			return fmt.Errorf("storing provenance: %w", err)
		}

		matches, err := m.MatchWithBlobID(content, blobID)
		if err != nil {
			return fmt.Errorf("matching content: %w", err)
		}

		for _, match := range matches {
			startLine, startCol := types.ComputeLineColumn(content, int(match.Location.Offset.Start))
			endLine, endCol := types.ComputeLineColumn(content, int(match.Location.Offset.End))
			match.Location.Source.Start.Line = startLine
			match.Location.Source.Start.Column = startCol
			match.Location.Source.End.Line = endLine
			match.Location.Source.End.Column = endCol
		}

		for _, match := range matches {
			matchCount++

			if err := s.AddMatch(match); err != nil {
				return fmt.Errorf("storing match: %w", err)
			}

			rule, ok := ruleMap[match.RuleID]
			if !ok {
				return fmt.Errorf("rule not found: %s", match.RuleID)
			}
			findingID := types.ComputeFindingID(rule.StructuralID, match.Groups)
			exists, err := s.FindingExists(findingID)
			if err != nil {
				return fmt.Errorf("checking finding: %w", err)
			}

			if !exists {
				findingCount++
				finding := &types.Finding{
					ID:     findingID,
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
		return fmt.Errorf("scanning Linear: %w", err)
	}

	if linearOutputFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Linear scan complete: %d matches, %d findings\n", matchCount, findingCount)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", linearOutputPath)

	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}
	return outputFindings(cmd, findings)
}
