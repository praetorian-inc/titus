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
)

var gitlabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "Scan GitLab projects via API",
	Long:  "Enumerate and scan GitLab projects without cloning",
}

var gitlabScanCmd = &cobra.Command{
	Use:   "scan [namespace/project]",
	Short: "Scan GitLab project or group",
	Long:  "Scan a single project, all projects in a group, or all projects for a user",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runGitLabScan,
}

func init() {
	gitlabScanCmd.Flags().StringVar(&gitlabToken, "token", "", "GitLab token (or use GITLAB_TOKEN env)")
	gitlabScanCmd.Flags().StringVar(&gitlabGroup, "group", "", "Scan all projects in group")
	gitlabScanCmd.Flags().StringVar(&gitlabUser, "user", "", "Scan all projects for user")
	gitlabScanCmd.Flags().StringVar(&gitlabBaseURL, "url", "", "GitLab base URL (default: gitlab.com)")
	gitlabScanCmd.Flags().StringVar(&gitlabOutputPath, "output", "titus.db", "Output database path")
	gitlabScanCmd.Flags().StringVar(&gitlabOutputFormat, "format", "human", "Output format: json, human")

	gitlabCmd.AddCommand(gitlabScanCmd)
}

func runGitLabScan(cmd *cobra.Command, args []string) error {
	// Get token from flag or environment
	token := gitlabToken
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("GitLab token required: use --token or GITLAB_TOKEN env")
	}

	// Parse project path if provided
	var project string
	if len(args) > 0 {
		project = args[0]
	}

	// Validate input
	if project == "" && gitlabGroup == "" && gitlabUser == "" {
		return fmt.Errorf("must specify namespace/project, --group, or --user")
	}

	// Load rules
	rules, err := loadRules("", "", "")
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	// Create matcher
	m, err := matcher.New(matcher.Config{Rules: rules})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	// Create store
	s, err := store.New(store.Config{Path: gitlabOutputPath})
	if err != nil {
		return fmt.Errorf("creating store: %w", err)
	}
	defer s.Close()

	// Create GitLab enumerator
	enumerator, err := enum.NewGitLabEnumerator(enum.GitLabConfig{
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
			exists, err := s.FindingExists(match.StructuralID)
			if err != nil {
				return fmt.Errorf("checking finding: %w", err)
			}

			if !exists {
				findingCount++
				finding := &types.Finding{
					ID:     match.StructuralID,
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

	return nil
}
