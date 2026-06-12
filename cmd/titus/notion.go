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
	notionToken        string
	notionConcurrency  int
	notionOutputPath   string
	notionOutputFormat string
	notionPageID       string
	notionWorkspace    string
	notionTeamspace    string
)

var notionCmd = &cobra.Command{
	Use:   "notion",
	Short: "Scan a Notion workspace for secrets",
	Long: `Scan an entire Notion workspace for secrets using the internal API.
Requires a token_v2 session cookie from an authenticated Notion session.

Authentication:
  Use --token or NOTION_TOKEN env var with a token_v2 session cookie.
  To obtain the token: open Notion in a browser, open DevTools, find the
  token_v2 cookie under Application > Cookies > www.notion.so.

Examples:
  titus notion --token <token_v2>
  titus notion --token <token_v2> --concurrency 20
  NOTION_TOKEN=<token_v2> titus notion --output notion-scan.db
  titus notion --token <token_v2> --page https://app.notion.com/p/Page-Title-abc123def456
  titus notion --token <token_v2> --page 37da484a-7dc4-80dd-936b-d247d86f7ef7
  titus notion --token <token_v2> --teamspace Engineering
  titus notion --token <token_v2> --workspace Praetorian --teamspace "Sales & Marketing"`,
	RunE: runNotionScan,
}

func init() {
	notionCmd.Flags().StringVar(&notionToken, "token", "", "Notion token_v2 session cookie (or NOTION_TOKEN env)")
	notionCmd.Flags().IntVar(&notionConcurrency, "concurrency", 10, "Number of parallel page fetchers")
	notionCmd.Flags().StringVar(&notionOutputPath, "output", "titus.db", "Output database path")
	notionCmd.Flags().StringVar(&notionOutputFormat, "format", "human", "Output format: json, human")
	notionCmd.Flags().StringVar(&notionPageID, "page", "", "Scan a single page (URL or page ID)")
	notionCmd.Flags().StringVar(&notionWorkspace, "workspace", "", "Workspace name or ID (for multi-workspace accounts)")
	notionCmd.Flags().StringVar(&notionTeamspace, "teamspace", "", "Scan only pages in this teamspace (name or ID)")
}

func runNotionScan(cmd *cobra.Command, args []string) error {
	token := notionToken
	if token == "" {
		token = os.Getenv("NOTION_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("notion token_v2 is required: use --token or NOTION_TOKEN env var")
	}

	var verboseWriter io.Writer
	if verbose {
		verboseWriter = cmd.ErrOrStderr()
	}

	enumerator, err := enum.NewNotionEnumerator(enum.NotionConfig{
		Token:       token,
		Concurrency: notionConcurrency,
		Verbose:     verboseWriter,
		PageID:      notionPageID,
		Workspace:   notionWorkspace,
		Teamspace:   notionTeamspace,
	})
	if err != nil {
		return fmt.Errorf("creating Notion enumerator: %w", err)
	}

	rules, err := loadRules("", "", "", scanRuleset, false)
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
		Path: notionOutputPath,
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
		return fmt.Errorf("scanning Notion: %w", err)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "Notion scan complete: %d matches, %d findings\n", matchCount, findingCount)
	fmt.Fprintf(cmd.ErrOrStderr(), "Results stored in: %s\n", notionOutputPath)

	if notionOutputFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}
	return outputFindings(cmd, findings)
}
