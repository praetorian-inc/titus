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
	slackToken        string
	slackCookie       string
	slackOutputPath   string
	slackOutputFormat string
	slackChannels     string
	slackRateLimit    float64
)

var slackCmd = &cobra.Command{
	Use:   "slack",
	Short: "Scan a Slack workspace for secrets",
	Long: `Scan an entire Slack workspace for secrets via the Slack Web API.
Enumerates channels, messages, and thread replies.

Authentication:
  Use --token or SLACK_TOKEN env var with a Slack token.
  Supported token types: xoxb- (bot), xoxp- (user), xoxc- (browser session).
  Browser session tokens (xoxc-) also require --cookie with the xoxd- session cookie.
  To get xoxc/xoxd: open Slack in browser → DevTools → Application →
    token: Local Storage → search for xoxc-
    cookie: Cookies → cookie named "d" (starts with xoxd-)

Examples:
  titus slack --token xoxb-xxx
  SLACK_TOKEN=xoxb-xxx titus slack
  titus slack --token xoxb-xxx --channels general,engineering
  titus slack --token xoxb-xxx --output slack-scan.db --format json
  titus slack --token xoxc-xxx --cookie xoxd-xxx -v          # browser session token`,
	RunE: runSlackScan,
}

func init() {
	slackCmd.Flags().StringVar(&slackToken, "token", "", "Slack API token (or SLACK_TOKEN env)")
	slackCmd.Flags().StringVar(&slackCookie, "cookie", "", "Slack session cookie (xoxd-...) — required for xoxc- tokens (or SLACK_COOKIE env)")
	slackCmd.Flags().StringVar(&slackOutputPath, "output", "titus.db", "Output database path")
	slackCmd.Flags().StringVar(&slackOutputFormat, "format", "human", "Output format: json, human")
	slackCmd.Flags().StringVar(&slackChannels, "channels", "", "Comma-separated channel names to scan (default: all)")
	slackCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules file or directory (merged with builtins)")
	slackCmd.Flags().StringVar(&scanRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	slackCmd.Flags().StringVar(&scanRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	slackCmd.Flags().StringVar(&scanRuleset, "ruleset", "default", "Ruleset to use: default, np.assets, np.hashes, all")
	slackCmd.Flags().BoolVar(&scanIncludeNoisy, "include-noisy", false, "Include noisy rules that may produce more false positives")
	slackCmd.Flags().Float64Var(&slackRateLimit, "rate-limit", 1.0, "API requests per second (default 1.0)")
}

func runSlackScan(cmd *cobra.Command, args []string) error {
	token := slackToken
	if token == "" {
		token = os.Getenv("SLACK_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("slack API token is required: use --token or SLACK_TOKEN env var")
	}

	cookie := slackCookie
	if cookie == "" {
		cookie = os.Getenv("SLACK_COOKIE")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewSlackEnumerator(enum.SlackConfig{
		Token:     token,
		Cookie:    cookie,
		RateLimit: slackRateLimit,
		Channels:  slackChannels,
		Verbose:   verboseWriter,
	})
	if err != nil {
		return fmt.Errorf("creating Slack enumerator: %w", err)
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
		Path: slackOutputPath,
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
		return fmt.Errorf("scanning Slack: %w", err)
	}

	if slackOutputFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Slack scan complete: %d matches, %d findings\n", matchCount, findingCount)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", slackOutputPath)

	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}
	return outputFindings(cmd, findings)
}
