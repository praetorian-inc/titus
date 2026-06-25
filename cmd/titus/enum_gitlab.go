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
	gitlabToken     string
	gitlabGroup     string
	gitlabUser      string
	gitlabBaseURL   string
	gitlabNoClone   bool
	gitlabGit       bool
	gitlabRateLimit float64
	gitlabJitter    float64
	gitlabYes       bool
)

var gitlabCmd = &cobra.Command{
	Use:   "gitlab [namespace/project]",
	Short: "Scan GitLab projects",
	Long: `Scan GitLab projects by cloning and scanning locally.
No API token needed for public projects.
Use --token or GITLAB_TOKEN for private projects and higher rate limits.
Use --git to scan full git history (slower but finds deleted secrets).

Stealth scanning:
  Use --jitter to add random delays between project clones.
  Combined with --rate-limit, it creates a random delay between the
  rate-limit (minimum) and jitter (maximum) values.
  Example: --rate-limit 300 --jitter 1200 = random 5-20 minute delays.`,
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

// registerGitLabFlags registers GitLab-specific (clone-related and connection) flags on the given FlagSet.
func registerGitLabFlags(fs *pflag.FlagSet) {
	fs.StringVar(&gitlabToken, "token", "", "GitLab token (or GITLAB_TOKEN env; optional for public projects)")
	fs.StringVar(&gitlabGroup, "group", "", "Scan all projects in group")
	fs.StringVar(&gitlabUser, "user", "", "Scan all projects for user")
	fs.StringVar(&gitlabBaseURL, "url", "", "GitLab base URL (default: gitlab.com)")
	fs.BoolVar(&gitlabNoClone, "no-clone", false, "Fetch files via API instead of cloning (requires token, no git history)")
	fs.BoolVar(&gitlabGit, "git", false, "Scan full git history (slower; default scans only current files)")
	fs.Float64Var(&gitlabRateLimit, "rate-limit", 0, "Delay in seconds between project clones (e.g., 2 or 0.5; 0 = no delay)")
	fs.Float64Var(&gitlabJitter, "jitter", 0, "Maximum random delay in seconds between project clones (e.g., 1200 for 20min; combined with --rate-limit as minimum)")
	fs.BoolVarP(&gitlabYes, "yes", "y", false, "Skip confirmation prompt for scan time estimate")
}

func init() {
	// Register service-specific flags on both the main command and the scan subcommand.
	registerGitLabFlags(gitlabScanCmd.Flags())
	registerGitLabFlags(gitlabCmd.Flags())

	// The scan subcommand also needs the shared enum flags so old invocations work.
	registerEnumScanFlags(gitlabScanCmd.Flags())

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
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Note: No GitLab token provided. Using unauthenticated access (public projects only).\n")
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Set GITLAB_TOKEN or use --token for private project access.\n\n")
	}

	if gitlabBaseURL != "" {
		insecure, err := enum.ValidateBaseURL(gitlabBaseURL)
		if err != nil {
			return fmt.Errorf("invalid --url: %w", err)
		}
		if insecure && token != "" {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: Using HTTP with an API token. Your token will be sent in plaintext.\n")
		}
	}

	var project string
	if len(args) > 0 {
		project = args[0]
	}

	// Resolve :auto: output path before running the scan pipeline.
	if enumOutput == ":auto:" {
		enumOutput = resolveAutoName(gitlabGroup, gitlabUser, project)
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

	ctx := cmd.Context()
	var enumerator enum.Enumerator

	if gitlabNoClone {
		enumerator = glEnum
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Enumerating projects...\n")
		projects, err := glEnum.ListProjectURLs(ctx)
		if err != nil {
			return fmt.Errorf("listing projects: %w", err)
		}

		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Found %d projects to scan\n\n", len(projects))

		cloneEnum := enum.NewCloneEnumerator(projects, enum.Config{
			MaxFileSize: 10 * 1024 * 1024,
		})
		cloneEnum.Git = gitlabGit
		cloneEnum.Token = token
		if gitlabRateLimit > 0 {
			cloneEnum.Delay = time.Duration(gitlabRateLimit * float64(time.Second))
		}
		if gitlabJitter > 0 {
			cloneEnum.Jitter = time.Duration(gitlabJitter * float64(time.Second))
		}

		// Estimate scan time and prompt for confirmation if delay/jitter is enabled.
		if cloneEnum.Jitter > 0 || cloneEnum.Delay > 0 {
			estimate := cloneEnum.EstimateScanTime()
			if estimate > 0 {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Estimated scan time: %s (with %d projects)\n", formatDuration(estimate), len(projects))
				if !gitlabYes {
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

	return runEnumScan(cmd, enumerator, "GitLab")
}
