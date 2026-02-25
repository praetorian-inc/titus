package main

import (
	"context"
	"fmt"
	"os"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
)

var (
	githubToken        string
	githubOrg          string
	githubUser         string
	githubOutputPath   string
	githubOutputFormat string
	githubNoClone      bool
	githubGit          bool
)

var githubCmd = &cobra.Command{
	Use:   "github [owner/repo]",
	Short: "Scan GitHub repositories",
	Long: `Scan GitHub repositories by cloning and scanning locally.
No API token needed for public repositories.
Use --token or GITHUB_TOKEN for private repos and higher rate limits.
Use --git to scan full git history (slower but finds deleted secrets).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGitHubScan,
}

var githubScanCmd = &cobra.Command{
	Use:   "scan [owner/repo]",
	Short: "Scan GitHub repository or organization",
	Long: `Scan a single repo (owner/repo), all repos in an org (--org), or all repos for a user (--user).
Repositories are cloned and scanned for current files by default.
No API token needed for public repositories.
Use --git to also scan full git history.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGitHubScan,
}

func init() {
	githubScanCmd.Flags().StringVar(&githubToken, "token", "", "GitHub API token (or GITHUB_TOKEN env; optional for public repos)")
	githubScanCmd.Flags().StringVar(&githubOrg, "org", "", "Scan all repositories in organization")
	githubScanCmd.Flags().StringVar(&githubUser, "user", "", "Scan all repositories for user")
	githubScanCmd.Flags().StringVar(&githubOutputPath, "output", "titus.db", "Output database path")
	githubScanCmd.Flags().StringVar(&githubOutputFormat, "format", "human", "Output format: json, human")
	githubScanCmd.Flags().BoolVar(&githubNoClone, "no-clone", false, "Fetch files via API instead of cloning (requires token, no git history)")
	githubScanCmd.Flags().BoolVar(&githubGit, "git", false, "Scan full git history (slower; default scans only current files)")

	githubCmd.Flags().StringVar(&githubToken, "token", "", "GitHub API token (or GITHUB_TOKEN env; optional for public repos)")
	githubCmd.Flags().StringVar(&githubOrg, "org", "", "Scan all repositories in organization")
	githubCmd.Flags().StringVar(&githubUser, "user", "", "Scan all repositories for user")
	githubCmd.Flags().StringVar(&githubOutputPath, "output", "titus.db", "Output database path")
	githubCmd.Flags().StringVar(&githubOutputFormat, "format", "human", "Output format: json, human")
	githubCmd.Flags().BoolVar(&githubNoClone, "no-clone", false, "Fetch files via API instead of cloning (requires token, no git history)")
	githubCmd.Flags().BoolVar(&githubGit, "git", false, "Scan full git history (slower; default scans only current files)")

	githubCmd.AddCommand(githubScanCmd)
}

func runGitHubScan(cmd *cobra.Command, args []string) error {
	token := githubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	if githubNoClone && token == "" {
		return fmt.Errorf("--no-clone requires a GitHub API token: use --token or GITHUB_TOKEN")
	}

	if token == "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Note: No GitHub token provided. Using unauthenticated access (60 requests/hour, public repos only).\n")
		fmt.Fprintf(cmd.ErrOrStderr(), "Set GITHUB_TOKEN or use --token for higher rate limits and private repo access.\n\n")
	}

	var owner, repo string
	if len(args) > 0 {
		parts := splitOwnerRepo(args[0])
		if len(parts) != 2 {
			return fmt.Errorf("invalid repository format, expected owner/repo (e.g., praetorian-inc/titus)")
		}
		owner, repo = parts[0], parts[1]
	}

	if repo == "" && githubOrg == "" && githubUser == "" {
		return fmt.Errorf("must specify owner/repo, --org, or --user")
	}

	ghEnum, err := enum.NewGitHubEnumerator(enum.GitHubConfig{
		Token: token,
		Owner: owner,
		Repo:  repo,
		Org:   githubOrg,
		User:  githubUser,
		Config: enum.Config{
			MaxFileSize: 10 * 1024 * 1024,
		},
	})
	if err != nil {
		return fmt.Errorf("creating GitHub client: %w", err)
	}

	rules, err := loadRules("", "", "")
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
		Path: githubOutputPath,
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
	var enumerator enum.Enumerator

	if githubNoClone {
		enumerator = ghEnum
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "Enumerating repositories...\n")
		repos, err := ghEnum.ListRepoURLs(ctx)
		if err != nil {
			return fmt.Errorf("listing repositories: %w", err)
		}

		fmt.Fprintf(cmd.ErrOrStderr(), "Found %d repositories to scan\n\n", len(repos))

		cloneEnum := enum.NewCloneEnumerator(repos, enum.Config{
			MaxFileSize: 10 * 1024 * 1024,
		})
		cloneEnum.Git = githubGit
		enumerator = cloneEnum
	}

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
		return fmt.Errorf("scanning GitHub: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "GitHub scan complete: %d matches, %d findings\n", matchCount, findingCount)
	fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", githubOutputPath)

	if githubOutputFormat == "json" {
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

// splitOwnerRepo splits "owner/repo" into ["owner", "repo"].
func splitOwnerRepo(s string) []string {
	result := make([]string, 0, 2)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}
