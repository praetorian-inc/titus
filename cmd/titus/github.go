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
)

var githubCmd = &cobra.Command{
	Use:   "github [owner/repo]",
	Short: "Scan GitHub repositories via API",
	Long:  "Scan GitHub repositories via API without cloning locally",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runGitHubScan,
}

var githubScanCmd = &cobra.Command{
	Use:   "scan [owner/repo]",
	Short: "Scan GitHub repository or organization",
	Long:  "Scan a single repo (owner/repo), all repos in an org (--org), or all repos for a user (--user)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runGitHubScan,
}

func init() {
	// Add flags to github scan command
	githubScanCmd.Flags().StringVar(&githubToken, "token", "", "GitHub API token (or use GITHUB_TOKEN env)")
	githubScanCmd.Flags().StringVar(&githubOrg, "org", "", "Scan all repositories in organization")
	githubScanCmd.Flags().StringVar(&githubUser, "user", "", "Scan all repositories for user")
	githubScanCmd.Flags().StringVar(&githubOutputPath, "output", "titus.db", "Output database path")
	githubScanCmd.Flags().StringVar(&githubOutputFormat, "format", "human", "Output format: json, human")

	// Add flags to root github command (for backward compatibility)
	githubCmd.Flags().StringVar(&githubToken, "token", "", "GitHub API token (or use GITHUB_TOKEN env)")
	githubCmd.Flags().StringVar(&githubOrg, "org", "", "Scan all repositories in organization")
	githubCmd.Flags().StringVar(&githubUser, "user", "", "Scan all repositories for user")
	githubCmd.Flags().StringVar(&githubOutputPath, "output", "titus.db", "Output database path")
	githubCmd.Flags().StringVar(&githubOutputFormat, "format", "human", "Output format: json, human")

	// Add scan as subcommand
	githubCmd.AddCommand(githubScanCmd)
}

func runGitHubScan(cmd *cobra.Command, args []string) error {
	// Get token from flag or environment
	token := githubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("GitHub API token required: use --token flag or GITHUB_TOKEN environment variable")
	}

	// Parse owner/repo if provided
	var owner, repo string
	if len(args) > 0 {
		// Parse "owner/repo" format
		parts := splitOwnerRepo(args[0])
		if len(parts) != 2 {
			return fmt.Errorf("invalid repository format, expected owner/repo (e.g., praetorian-inc/titus)")
		}
		owner, repo = parts[0], parts[1]
	}

	// Validate that at least one target is specified
	if repo == "" && githubOrg == "" && githubUser == "" {
		return fmt.Errorf("must specify owner/repo, --org, or --user")
	}

	// Load rules
	rules, err := loadRules("", "", "")
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	// Create matcher
	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: 3,
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	// Create store
	s, err := store.New(store.Config{
		Path: githubOutputPath,
	})
	if err != nil {
		return fmt.Errorf("creating store: %w", err)
	}
	defer s.Close()

	// Store rules for foreign key constraints
	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("storing rule: %w", err)
		}
	}

	// Create GitHub enumerator
	enumerator, err := enum.NewGitHubEnumerator(enum.GitHubConfig{
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
		return fmt.Errorf("creating GitHub enumerator: %w", err)
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

			// Create finding (deduplicated by structural ID)
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
		return fmt.Errorf("scanning GitHub: %w", err)
	}

	// Output results
	fmt.Fprintf(cmd.OutOrStdout(), "GitHub scan complete: %d matches, %d findings\n", matchCount, findingCount)
	fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", githubOutputPath)

	// Get results for output
	if githubOutputFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	// Human format outputs findings
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
