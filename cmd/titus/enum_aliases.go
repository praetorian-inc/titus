package main

import (
	"github.com/spf13/cobra"
)

// Hidden deprecated aliases — one per old top-level command.
// Each re-registers the shared enum scan flags plus its service-specific flags so
// old invocations (e.g. "titus confluence --token x") continue to work.

var githubAliasCmd = &cobra.Command{
	Use:        "github",
	Hidden:     true,
	Deprecated: "use 'titus enum github' instead",
	Args:       cobra.MaximumNArgs(1),
	RunE:       runGitHubScan,
}

var githubAliasScanCmd = &cobra.Command{
	Use:        "scan",
	Hidden:     true,
	Deprecated: "use 'titus enum github scan' instead",
	Args:       cobra.MaximumNArgs(1),
	RunE:       runGitHubScan,
}

var gitlabAliasCmd = &cobra.Command{
	Use:        "gitlab",
	Hidden:     true,
	Deprecated: "use 'titus enum gitlab' instead",
	Args:       cobra.MaximumNArgs(1),
	RunE:       runGitLabScan,
}

var gitlabAliasScanCmd = &cobra.Command{
	Use:        "scan",
	Hidden:     true,
	Deprecated: "use 'titus enum gitlab scan' instead",
	Args:       cobra.MaximumNArgs(1),
	RunE:       runGitLabScan,
}

var slackAliasCmd = &cobra.Command{
	Use:        "slack",
	Hidden:     true,
	Deprecated: "use 'titus enum slack' instead",
	RunE:       runSlackScan,
}

var notionAliasCmd = &cobra.Command{
	Use:        "notion",
	Hidden:     true,
	Deprecated: "use 'titus enum notion' instead",
	RunE:       runNotionScan,
}

var linearAliasCmd = &cobra.Command{
	Use:        "linear",
	Hidden:     true,
	Deprecated: "use 'titus enum linear' instead",
	RunE:       runLinearScan,
}

var confluenceAliasCmd = &cobra.Command{
	Use:        "confluence",
	Hidden:     true,
	Deprecated: "use 'titus enum confluence' instead",
	RunE:       runConfluenceScan,
}

var jiraAliasCmd = &cobra.Command{
	Use:        "jira",
	Hidden:     true,
	Deprecated: "use 'titus enum jira' instead",
	RunE:       runJiraScan,
}

var sharepointAliasCmd = &cobra.Command{
	Use:        "sharepoint",
	Hidden:     true,
	Deprecated: "use 'titus enum microsoft sharepoint' instead",
	RunE:       runSharePointScan,
}

func init() {
	// github alias
	registerEnumScanFlags(githubAliasCmd.Flags())
	registerGitHubFlags(githubAliasCmd.Flags())
	registerEnumScanFlags(githubAliasScanCmd.Flags())
	registerGitHubFlags(githubAliasScanCmd.Flags())
	githubAliasCmd.AddCommand(githubAliasScanCmd)
	rootCmd.AddCommand(githubAliasCmd)

	// gitlab alias
	registerEnumScanFlags(gitlabAliasCmd.Flags())
	registerGitLabFlags(gitlabAliasCmd.Flags())
	registerEnumScanFlags(gitlabAliasScanCmd.Flags())
	registerGitLabFlags(gitlabAliasScanCmd.Flags())
	gitlabAliasCmd.AddCommand(gitlabAliasScanCmd)
	rootCmd.AddCommand(gitlabAliasCmd)

	// slack alias
	registerEnumScanFlags(slackAliasCmd.Flags())
	registerSlackFlags(slackAliasCmd.Flags())
	rootCmd.AddCommand(slackAliasCmd)

	// notion alias
	registerEnumScanFlags(notionAliasCmd.Flags())
	registerNotionFlags(notionAliasCmd.Flags())
	rootCmd.AddCommand(notionAliasCmd)

	// linear alias
	registerEnumScanFlags(linearAliasCmd.Flags())
	registerLinearFlags(linearAliasCmd.Flags())
	rootCmd.AddCommand(linearAliasCmd)

	// confluence alias
	registerEnumScanFlags(confluenceAliasCmd.Flags())
	registerConfluenceFlags(confluenceAliasCmd.Flags())
	rootCmd.AddCommand(confluenceAliasCmd)

	// jira alias
	registerEnumScanFlags(jiraAliasCmd.Flags())
	registerJiraFlags(jiraAliasCmd.Flags())
	rootCmd.AddCommand(jiraAliasCmd)

	// sharepoint alias (also needs microsoft auth flags)
	registerEnumScanFlags(sharepointAliasCmd.Flags())
	registerMicrosoftFlags(sharepointAliasCmd.Flags())
	registerSharePointFlags(sharepointAliasCmd.Flags())
	rootCmd.AddCommand(sharepointAliasCmd)
}
