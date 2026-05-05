package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/spf13/cobra"
)

var (
	githubToken     string
	githubBaseURL   string
	githubOrg       string
	githubUser      string
	githubNoClone   bool
	githubGit       bool
	githubSkipForks bool
	githubRateLimit float64
)

var githubCmd = &cobra.Command{
	Use:   "github [owner/repo]",
	Short: "Scan GitHub repositories for secrets",
	Long: `Scan GitHub repositories by cloning and scanning locally.
Supports github.com and GitHub Enterprise Server instances.

Authentication:
  No token needed for public repositories (60 requests/hour).
  Use --token or GITHUB_TOKEN env var for private repos and higher rate limits (5000/hour).

GitHub Enterprise:
  Use --url or GITHUB_BASE_URL env var to point at a GHE Server instance.
  Example: --url https://github.example.com

Rate limiting:
  Use --rate-limit to add a delay between repository clones (recommended for large, self-hosted orgs).
  Example: --rate-limit 2 adds a 2-second delay between each repo.

Examples:
  titus github praetorian-inc/titus                          # single public repo
  titus github --token ghp_xxx --org praetorian-inc          # all repos in org
  titus github --url https://ghe.corp.com --token ghp_xxx --org myorg --rate-limit 2
  titus github --token ghp_xxx --user octocat --git          # user repos with full history`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGitHubScan,
}

var githubScanCmd = &cobra.Command{
	Use:   "scan [owner/repo]",
	Short: "Scan GitHub repository or organization",
	Long: `Scan a single repo (owner/repo), all repos in an org (--org), or all repos for a user (--user).
Repositories are cloned and scanned for current files by default.
Use --git to also scan full git history (slower but finds deleted secrets).
Use --no-clone to fetch files via API instead of cloning (requires token).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGitHubScan,
}

func init() {
	registerGitHubFlags(githubScanCmd)
	registerGitHubFlags(githubCmd)
	githubCmd.AddCommand(githubScanCmd)
}

// registerGitHubFlags binds every flag the github subcommand supports onto cmd.
// Used for both `titus github` and `titus github scan`.
func registerGitHubFlags(cmd *cobra.Command) {
	addRulesFlags(cmd)
	addOutputFlags(cmd)
	addPipelineFlags(cmd)
	cmd.Flags().StringVar(&githubToken, "token", "", "GitHub API token (or GITHUB_TOKEN env; optional for public repos)")
	cmd.Flags().StringVar(&githubBaseURL, "url", "", "GitHub Enterprise base URL (or GITHUB_BASE_URL env; e.g., https://github.example.com)")
	cmd.Flags().StringVar(&githubOrg, "org", "", "Scan all repositories in organization")
	cmd.Flags().StringVar(&githubUser, "user", "", "Scan all repositories for user")
	cmd.Flags().BoolVar(&githubNoClone, "no-clone", false, "Fetch files via API instead of cloning (requires token, no git history)")
	cmd.Flags().BoolVar(&githubGit, "git", false, "Scan full git history (slower; default scans only current files)")
	cmd.Flags().BoolVar(&githubSkipForks, "skip-forks", false, "Skip forked repositories when scanning orgs or users")
	cmd.Flags().Float64Var(&githubRateLimit, "rate-limit", 0, "Delay in seconds between repository clones (e.g., 2 or 0.5; 0 = no delay)")
}

func runGitHubScan(cmd *cobra.Command, args []string) error {
	token := githubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	baseURL := githubBaseURL
	if baseURL == "" {
		baseURL = os.Getenv("GITHUB_BASE_URL")
	}

	if githubNoClone && token == "" {
		return fmt.Errorf("--no-clone requires a GitHub API token: use --token or GITHUB_TOKEN")
	}

	if token == "" {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Note: No GitHub token provided. Using unauthenticated access (60 requests/hour, public repos only).\n")
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Set GITHUB_TOKEN or use --token for higher rate limits and private repo access.\n\n")
	}

	if baseURL != "" {
		insecure, err := enum.ValidateBaseURL(baseURL)
		if err != nil {
			return fmt.Errorf("invalid --url: %w", err)
		}
		if insecure && token != "" {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: Using HTTP with an API token. Your token will be sent in plaintext.\n")
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Using GitHub Enterprise: %s\n", baseURL)
	}

	var owner, repo string
	if len(args) > 0 {
		parts := splitOwnerRepo(args[0])
		if len(parts) != 2 {
			return fmt.Errorf("invalid repository format, expected owner/repo (e.g., praetorian-inc/titus)")
		}
		owner, repo = parts[0], parts[1]
	}

	if scanOutputPath == ":auto:" {
		scanOutputPath = resolveAutoName(githubOrg, githubUser, repo)
	}

	if repo == "" && githubOrg == "" && githubUser == "" {
		return fmt.Errorf("must specify owner/repo, --org, or --user")
	}

	ghEnum, err := enum.NewGitHubEnumerator(enum.GitHubConfig{
		Token:     token,
		BaseURL:   baseURL,
		Owner:     owner,
		Repo:      repo,
		Org:       githubOrg,
		User:      githubUser,
		SkipForks: githubSkipForks,
		Config: enum.Config{
			MaxFileSize: scanMaxFileSize,
		},
	})
	if err != nil {
		return fmt.Errorf("creating GitHub client: %w", err)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	var enumerator enum.Enumerator
	if githubNoClone {
		enumerator = ghEnum
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Enumerating repositories...\n")
		repos, err := ghEnum.ListRepoURLs(ctx)
		if err != nil {
			return fmt.Errorf("listing repositories: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Found %d repositories to scan\n\n", len(repos))

		limits, err := resolveExtractionLimits()
		if err != nil {
			return err
		}
		cloneEnum := enum.NewCloneEnumerator(repos, enum.Config{
			MaxFileSize:     scanMaxFileSize,
			IgnoreFile:      scanIgnoreFile,
			ExtractArchives: string(scanExtractArchivesFlag),
			ExtractLimits:   limits,
			NumReaders:      scanReaders,
		})
		cloneEnum.Git = githubGit
		cloneEnum.Token = token
		if githubRateLimit > 0 {
			cloneEnum.Delay = time.Duration(githubRateLimit * float64(time.Second))
		}
		enumerator = cloneEnum
	}

	target := repo
	if githubOrg != "" {
		target = githubOrg
	} else if githubUser != "" {
		target = githubUser
	} else if owner != "" {
		target = owner + "/" + repo
	}

	return runPipeline(ctx, cmd, enumerator, pipelineOpts{
		Target:        target,
		OutputPath:    scanOutputPath,
		OutputFormat:  scanOutputFormat,
		Accessibility: resolveRemoteAccessibility(scanAccessibility),
	})
}

// resolveRemoteAccessibility maps the --accessibility flag for subcommands that
// scan remote-only targets (no local checkout to inspect). On "auto" we default
// to public so that auto-detection's "fall back to private" behavior — designed
// for local clones — does not silently apply a -25 penalty to every finding.
// Explicit "public"/"private" are still honored.
func resolveRemoteAccessibility(flag string) Accessibility {
	if flag == "auto" || flag == "" {
		return AccessibilityPublic
	}
	return ResolveAccessibility(flag, "", "")
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
