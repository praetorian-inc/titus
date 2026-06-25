package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	githubJitter    float64
	githubYes       bool
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

Stealth scanning:
  Use --jitter to add random delays between repository clones.
  Combined with --rate-limit, it creates a random delay between the
  rate-limit (minimum) and jitter (maximum) values.
  Example: --rate-limit 300 --jitter 1200 = random 5-20 minute delays.

Examples:
  titus enum github praetorian-inc/titus                          # single public repo
  titus enum github --token ghp_xxx --org praetorian-inc          # all repos in org
  titus enum github --url https://ghe.corp.com --token ghp_xxx --org myorg --rate-limit 2
  titus enum github --token ghp_xxx --user octocat --git          # user repos with full history
  titus enum github --token ghp_xxx --org myorg --jitter 1200             # 0-20min random delay between clones
  titus enum github --token ghp_xxx --org myorg --rate-limit 300 --jitter 1200  # 5-20min random delay (stealth)`,
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

// registerGitHubFlags registers GitHub-specific (clone-related and connection) flags on the given FlagSet.
func registerGitHubFlags(fs *pflag.FlagSet) {
	fs.StringVar(&githubToken, "token", "", "GitHub API token (or GITHUB_TOKEN env; optional for public repos)")
	fs.StringVar(&githubBaseURL, "url", "", "GitHub Enterprise base URL (or GITHUB_BASE_URL env; e.g., https://github.example.com)")
	fs.StringVar(&githubOrg, "org", "", "Scan all repositories in organization")
	fs.StringVar(&githubUser, "user", "", "Scan all repositories for user")
	fs.BoolVar(&githubNoClone, "no-clone", false, "Fetch files via API instead of cloning (requires token, no git history)")
	fs.BoolVar(&githubGit, "git", false, "Scan full git history (slower; default scans only current files)")
	fs.BoolVar(&githubSkipForks, "skip-forks", false, "Skip forked repositories when scanning orgs or users")
	fs.Float64Var(&githubRateLimit, "rate-limit", 0, "Delay in seconds between repository clones (e.g., 2 or 0.5; 0 = no delay)")
	fs.Float64Var(&githubJitter, "jitter", 0, "Maximum random delay in seconds between repository clones (e.g., 1200 for 20min; combined with --rate-limit as minimum)")
	fs.BoolVarP(&githubYes, "yes", "y", false, "Skip confirmation prompt for scan time estimate")
}

func init() {
	// Register service-specific flags on both the main command and the scan subcommand.
	registerGitHubFlags(githubScanCmd.Flags())
	registerGitHubFlags(githubCmd.Flags())

	// The scan subcommand also needs the shared enum flags so old invocations work.
	registerEnumScanFlags(githubScanCmd.Flags())

	githubCmd.AddCommand(githubScanCmd)
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

	// Resolve :auto: output path before running the scan pipeline.
	if enumOutput == ":auto:" {
		enumOutput = resolveAutoName(githubOrg, githubUser, repo)
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
			MaxFileSize: 10 * 1024 * 1024,
		},
	})
	if err != nil {
		return fmt.Errorf("creating GitHub client: %w", err)
	}

	ctx := cmd.Context()
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

		cloneEnum := enum.NewCloneEnumerator(repos, enum.Config{
			MaxFileSize: 10 * 1024 * 1024,
		})
		cloneEnum.Git = githubGit
		cloneEnum.Token = token
		if githubRateLimit > 0 {
			cloneEnum.Delay = time.Duration(githubRateLimit * float64(time.Second))
		}
		if githubJitter > 0 {
			cloneEnum.Jitter = time.Duration(githubJitter * float64(time.Second))
		}

		// Estimate scan time and prompt for confirmation if delay/jitter is enabled.
		if cloneEnum.Jitter > 0 || cloneEnum.Delay > 0 {
			estimate := cloneEnum.EstimateScanTime()
			if estimate > 0 {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Estimated scan time: %s (with %d repos)\n", formatDuration(estimate), len(repos))
				if !githubYes {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Continue? [Y/n] ")
					var response string
					_, _ = fmt.Scanln(&response)
					response = strings.TrimSpace(strings.ToLower(response))
					if response == "n" || response == "no" {
						return fmt.Errorf("scan cancelled by user")
					}
				}
			}
		}

		enumerator = cloneEnum
	}

	return runEnumScan(cmd, enumerator, "GitHub")
}

// formatDuration formats a duration in a human-friendly way.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	if hours >= 24 {
		days := hours / 24
		hours = hours % 24
		if hours > 0 {
			return fmt.Sprintf("%dd %dh", days, hours)
		}
		return fmt.Sprintf("%dd", days)
	}
	if mins > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dh", hours)
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
