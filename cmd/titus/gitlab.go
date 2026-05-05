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
	gitlabToken     string
	gitlabGroup     string
	gitlabUser      string
	gitlabBaseURL   string
	gitlabNoClone   bool
	gitlabGit       bool
	gitlabRateLimit float64
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
	registerGitLabFlags(gitlabScanCmd)
	registerGitLabFlags(gitlabCmd)
	gitlabCmd.AddCommand(gitlabScanCmd)
}

// registerGitLabFlags binds every flag the gitlab subcommand supports onto cmd.
// Used for both `titus gitlab` and `titus gitlab scan`.
func registerGitLabFlags(cmd *cobra.Command) {
	addRulesFlags(cmd)
	addOutputFlags(cmd)
	addPipelineFlags(cmd)
	cmd.Flags().StringVar(&gitlabToken, "token", "", "GitLab token (or GITLAB_TOKEN env; optional for public projects)")
	cmd.Flags().StringVar(&gitlabGroup, "group", "", "Scan all projects in group")
	cmd.Flags().StringVar(&gitlabUser, "user", "", "Scan all projects for user")
	cmd.Flags().StringVar(&gitlabBaseURL, "url", "", "GitLab base URL (default: gitlab.com)")
	cmd.Flags().BoolVar(&gitlabNoClone, "no-clone", false, "Fetch files via API instead of cloning (requires token, no git history)")
	cmd.Flags().BoolVar(&gitlabGit, "git", false, "Scan full git history (slower; default scans only current files)")
	cmd.Flags().Float64Var(&gitlabRateLimit, "rate-limit", 0, "Delay in seconds between project clones (e.g., 2 or 0.5; 0 = no delay)")
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

	if scanOutputPath == ":auto:" {
		scanOutputPath = resolveAutoName(gitlabGroup, gitlabUser, project)
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
			MaxFileSize: scanMaxFileSize,
		},
	})
	if err != nil {
		return fmt.Errorf("creating GitLab client: %w", err)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

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
			MaxFileSize: scanMaxFileSize,
			IgnoreFile:  scanIgnoreFile,
		})
		cloneEnum.Git = gitlabGit
		cloneEnum.Token = token
		if gitlabRateLimit > 0 {
			cloneEnum.Delay = time.Duration(gitlabRateLimit * float64(time.Second))
		}
		enumerator = cloneEnum
	}

	target := project
	if gitlabGroup != "" {
		target = gitlabGroup
	} else if gitlabUser != "" {
		target = gitlabUser
	}

	return runPipeline(ctx, cmd, enumerator, pipelineOpts{
		Target:       target,
		OutputPath:   scanOutputPath,
		OutputFormat: scanOutputFormat,
		TokenEnvVar:  "GITLAB_TOKEN",
	})
}
