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
	gitlabToken        string
	gitlabGroup        string
	gitlabUser         string
	gitlabBaseURL      string
	gitlabOutputPath   string
	gitlabOutputFormat string
	gitlabNoClone      bool
	gitlabGit          bool
)

var gitlabCmd = &cobra.Command{
	Use:   "gitlab [namespace/project]",
	Short: "Scan GitLab projects",
	Long: `Scan GitLab projects by cloning and scanning locally.
No API token needed for public projects.
Use --token or GITLAB_TOKEN for private projects and higher rate limits.
Use --git to scan full git history (slower but finds deleted secrets).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGitLabScan,
}

var gitlabScanCmd = &cobra.Command{
	Use:   "scan [namespace/project]",
	Short: "Scan GitLab project or group",
	Long: `Scan a single project, all projects in a group, or all projects for a user.
Projects are cloned and scanned for current files by default.
No API token needed for public projects.
Use --git to also scan full git history.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGitLabScan,
}

func init() {
	gitlabScanCmd.Flags().StringVar(&gitlabToken, "token", "", "GitLab token (or GITLAB_TOKEN env; optional for public projects)")
	gitlabScanCmd.Flags().StringVar(&gitlabGroup, "group", "", "Scan all projects in group")
	gitlabScanCmd.Flags().StringVar(&gitlabUser, "user", "", "Scan all projects for user")
	gitlabScanCmd.Flags().StringVar(&gitlabBaseURL, "url", "", "GitLab base URL (default: gitlab.com)")
	gitlabScanCmd.Flags().StringVar(&gitlabOutputPath, "output", "titus.db", "Output database path")
	gitlabScanCmd.Flags().StringVar(&gitlabOutputFormat, "format", "human", "Output format: json, human")
	gitlabScanCmd.Flags().BoolVar(&gitlabNoClone, "no-clone", false, "Fetch files via API instead of cloning (requires token, no git history)")
	gitlabScanCmd.Flags().BoolVar(&gitlabGit, "git", false, "Scan full git history (slower; default scans only current files)")

	gitlabCmd.Flags().StringVar(&gitlabToken, "token", "", "GitLab token (or GITLAB_TOKEN env; optional for public projects)")
	gitlabCmd.Flags().StringVar(&gitlabGroup, "group", "", "Scan all projects in group")
	gitlabCmd.Flags().StringVar(&gitlabUser, "user", "", "Scan all projects for user")
	gitlabCmd.Flags().StringVar(&gitlabBaseURL, "url", "", "GitLab base URL (default: gitlab.com)")
	gitlabCmd.Flags().StringVar(&gitlabOutputPath, "output", "titus.db", "Output database path")
	gitlabCmd.Flags().StringVar(&gitlabOutputFormat, "format", "human", "Output format: json, human")
	gitlabCmd.Flags().BoolVar(&gitlabNoClone, "no-clone", false, "Fetch files via API instead of cloning (requires token, no git history)")
	gitlabCmd.Flags().BoolVar(&gitlabGit, "git", false, "Scan full git history (slower; default scans only current files)")

	gitlabCmd.AddCommand(gitlabScanCmd)
}

func runGitLabScan(cmd *cobra.Command, args []string) error {
	token := gitlabToken
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}

	if gitlabNoClone && token == "" {
		return fmt.Errorf("--no-clone requires a GitLab token: use --token or GITLAB_TOKEN")
	}

	if token == "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Note: No GitLab token provided. Using unauthenticated access (public projects only).\n")
		fmt.Fprintf(cmd.ErrOrStderr(), "Set GITLAB_TOKEN or use --token for private project access.\n\n")
	}

	var project string
	if len(args) > 0 {
		project = args[0]
	}

	if project == "" && gitlabGroup == "" && gitlabUser == "" {
		return fmt.Errorf("must specify namespace/project, --group, or --user")
	}

	glEnum, err := enum.NewGitLabEnumerator(enum.GitLabConfig{
		Token:   token,
		BaseURL: gitlabBaseURL,
		Project: project,
		Group:   gitlabGroup,
		User:    gitlabUser,
		Config: enum.Config{
			MaxFileSize: 10 * 1024 * 1024,
		},
	})
	if err != nil {
		return fmt.Errorf("creating GitLab client: %w", err)
	}

	rules, err := loadRules("", "", "")
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	m, err := matcher.New(matcher.Config{Rules: rules})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	s, err := store.New(store.Config{Path: gitlabOutputPath})
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

	if gitlabNoClone {
		enumerator = glEnum
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "Enumerating projects...\n")
		projects, err := glEnum.ListProjectURLs(ctx)
		if err != nil {
			return fmt.Errorf("listing projects: %w", err)
		}

		fmt.Fprintf(cmd.ErrOrStderr(), "Found %d projects to scan\n\n", len(projects))

		cloneEnum := enum.NewCloneEnumerator(projects, enum.Config{
			MaxFileSize: 10 * 1024 * 1024,
		})
		cloneEnum.Git = gitlabGit
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
		return fmt.Errorf("scanning: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "GitLab scan complete: %d matches, %d findings\n", matchCount, findingCount)
	fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", gitlabOutputPath)

	if gitlabOutputFormat == "json" {
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
