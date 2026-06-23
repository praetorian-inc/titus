package main

import (
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
	jiraToken         string
	jiraUsername       string
	jiraBaseURL       string
	jiraOutputPath    string
	jiraOutputFormat  string
	jiraProjects      string
	jiraRateLimit     float64
	jiraAllowInsecure bool
)

var jiraCmd = &cobra.Command{
	Use:   "jira",
	Short: "Scan a Jira instance for secrets",
	Long: `Scan an entire Jira instance for secrets via the REST API.
Enumerates issue descriptions and comments across all projects.
Supports both Jira Cloud (API v3) and Jira Server/Data Center (API v2),
with automatic version detection.

Authentication:
  For Jira Cloud: use --username and --token with an API token.
  For Jira Server/Data Center: use --token with a PAT (Personal Access Token).
  Create a Cloud API token at: https://id.atlassian.com/manage-profile/security/api-tokens

Examples:
  titus jira --base-url https://mysite.atlassian.net --username user@example.com --token ATATT...
  JIRA_BASE_URL=https://mysite.atlassian.net JIRA_USERNAME=user@example.com JIRA_TOKEN=ATATT... titus jira
  titus jira --base-url https://jira.internal --token PAT_TOKEN --projects DEV,OPS
  titus jira --base-url http://jira.local:8080 --token PAT --allow-insecure`,
	RunE: runJiraScan,
}

func init() {
	jiraCmd.Flags().StringVar(&jiraToken, "token", "", "Jira API token or PAT (or JIRA_TOKEN env)")
	jiraCmd.Flags().StringVar(&jiraUsername, "username", "", "Jira username for Cloud basic auth (or JIRA_USERNAME env)")
	jiraCmd.Flags().StringVar(&jiraBaseURL, "base-url", "", "Jira base URL (or JIRA_BASE_URL env)")
	jiraCmd.Flags().StringVar(&jiraOutputPath, "output", "titus.db", "Output database path")
	jiraCmd.Flags().StringVar(&jiraOutputFormat, "format", "human", "Output format: json, human")
	jiraCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules file or directory (merged with builtins)")
	jiraCmd.Flags().StringVar(&scanRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	jiraCmd.Flags().StringVar(&scanRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	jiraCmd.Flags().StringVar(&scanRuleset, "ruleset", "default", "Ruleset to use: default, np.assets, np.hashes, all")
	jiraCmd.Flags().BoolVar(&scanIncludeNoisy, "include-noisy", false, "Include noisy rules that may produce more false positives")
	jiraCmd.Flags().StringVar(&jiraProjects, "projects", "", "Comma-separated project keys to scan (empty = all)")
	jiraCmd.Flags().Float64Var(&jiraRateLimit, "rate-limit", 5.0, "Requests per second")
	jiraCmd.Flags().BoolVar(&jiraAllowInsecure, "allow-insecure", false, "Allow plaintext HTTP base URLs (for internal instances)")
}

func runJiraScan(cmd *cobra.Command, args []string) error {
	token := jiraToken
	if token == "" {
		token = os.Getenv("JIRA_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("jira API token is required: use --token or JIRA_TOKEN env var")
	}

	username := jiraUsername
	if username == "" {
		username = os.Getenv("JIRA_USERNAME")
	}

	baseURL := jiraBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("JIRA_BASE_URL")
	}
	if baseURL == "" {
		return fmt.Errorf("jira base URL is required: use --base-url or JIRA_BASE_URL env var")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewJiraEnumerator(enum.JiraConfig{
		Token:             token,
		Username:          username,
		BaseURL:           baseURL,
		RateLimit:         jiraRateLimit,
		Projects:          jiraProjects,
		AllowInsecureHTTP: jiraAllowInsecure,
		Verbose:           verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Jira enumerator: %w", err)
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
		Path: jiraOutputPath,
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

	ctx := cmd.Context()
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
		return fmt.Errorf("scanning Jira: %w", err)
	}

	if jiraOutputFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Jira scan complete: %d matches, %d findings\n", matchCount, findingCount)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", jiraOutputPath)

	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}
	return outputFindings(cmd, findings)
}
