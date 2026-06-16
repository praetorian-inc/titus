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
	confluenceToken        string
	confluenceUsername     string
	confluenceBaseURL      string
	confluenceOutputPath   string
	confluenceOutputFormat string
	confluenceSpaces       string
)

var confluenceCmd = &cobra.Command{
	Use:   "confluence",
	Short: "Scan a Confluence instance for secrets",
	Long: `Scan an entire Confluence instance for secrets via the REST API.
Enumerates pages, blog posts, and comments across all spaces.

Authentication:
  For Confluence Cloud: use --username and --token with an API token.
  For Confluence Server/Data Center: use --token with a PAT (Personal Access Token).
  Create a Cloud API token at: https://id.atlassian.com/manage-profile/security/api-tokens

Examples:
  titus confluence --base-url https://mysite.atlassian.net/wiki --username user@example.com --token ATATT...
  CONFLUENCE_BASE_URL=https://mysite.atlassian.net/wiki CONFLUENCE_TOKEN=ATATT... titus confluence
  titus confluence --base-url https://mysite.atlassian.net/wiki --token PAT_TOKEN --spaces DEV,OPS`,
	RunE: runConfluenceScan,
}

func init() {
	confluenceCmd.Flags().StringVar(&confluenceToken, "token", "", "Confluence API token or PAT (or CONFLUENCE_TOKEN env)")
	confluenceCmd.Flags().StringVar(&confluenceUsername, "username", "", "Confluence username for Cloud basic auth (or CONFLUENCE_USERNAME env)")
	confluenceCmd.Flags().StringVar(&confluenceBaseURL, "base-url", "", "Confluence base URL (or CONFLUENCE_BASE_URL env)")
	confluenceCmd.Flags().StringVar(&confluenceOutputPath, "output", "titus.db", "Output database path")
	confluenceCmd.Flags().StringVar(&confluenceOutputFormat, "format", "human", "Output format: json, human")
	confluenceCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules file or directory (merged with builtins)")
	confluenceCmd.Flags().StringVar(&scanRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	confluenceCmd.Flags().StringVar(&scanRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	confluenceCmd.Flags().StringVar(&scanRuleset, "ruleset", "default", "Ruleset to use: default, np.assets, np.hashes, all")
	confluenceCmd.Flags().BoolVar(&scanIncludeNoisy, "include-noisy", false, "Include noisy rules that may produce more false positives")
	confluenceCmd.Flags().StringVar(&confluenceSpaces, "spaces", "", "Comma-separated space keys to scan (empty = all)")
}

func runConfluenceScan(cmd *cobra.Command, args []string) error {
	token := confluenceToken
	if token == "" {
		token = os.Getenv("CONFLUENCE_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("confluence API token is required: use --token or CONFLUENCE_TOKEN env var")
	}

	username := confluenceUsername
	if username == "" {
		username = os.Getenv("CONFLUENCE_USERNAME")
	}

	baseURL := confluenceBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("CONFLUENCE_BASE_URL")
	}
	if baseURL == "" {
		return fmt.Errorf("confluence base URL is required: use --base-url or CONFLUENCE_BASE_URL env var")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewConfluenceEnumerator(enum.ConfluenceConfig{
		Token:    token,
		Username: username,
		BaseURL:  baseURL,
		Spaces:   confluenceSpaces,
		Verbose:  verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Confluence enumerator: %w", err)
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
		Path: confluenceOutputPath,
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
		return fmt.Errorf("scanning Confluence: %w", err)
	}

	if confluenceOutputFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Confluence scan complete: %d matches, %d findings\n", matchCount, findingCount)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", confluenceOutputPath)

	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}
	return outputFindings(cmd, findings)
}
