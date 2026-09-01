package main

import (
	"fmt"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	enumOutput       string
	enumFormat       string
	enumRulesPath    string
	enumRulesInclude string
	enumRulesExclude string
	enumRuleset      string
	enumIncludeNoisy bool
)

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate remote services for secrets",
	Long: `Enumerate remote services (GitHub, GitLab, Slack, Notion, Linear, Confluence, Jira, Microsoft 365, ServiceNow, Trello)
for secrets using detection rules.`,
}

// registerEnumScanFlags registers the shared enumeration flags on the given FlagSet.
// It is used for enumCmd persistent flags and for each hidden alias's local flags.
func registerEnumScanFlags(fs *pflag.FlagSet) {
	fs.StringVar(&enumOutput, "output", "titus.db", "Output database path (:memory: for in-memory, :auto: to derive from target name)")
	fs.StringVar(&enumFormat, "format", "human", "Output format: json, human")
	fs.StringVar(&enumRulesPath, "rules", "", "Path to custom rules file or directory (merged with builtins)")
	fs.StringVar(&enumRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	fs.StringVar(&enumRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	fs.StringVar(&enumRuleset, "ruleset", "default", "Ruleset to use: default, np.assets, np.hashes, all")
	fs.BoolVar(&enumIncludeNoisy, "include-noisy", false, "Include noisy rules that may produce more false positives")
}

func init() {
	registerEnumScanFlags(enumCmd.PersistentFlags())
	enumCmd.AddCommand(githubCmd, gitlabCmd, slackCmd, notionCmd, linearCmd, confluenceCmd, jiraCmd, microsoftCmd, gdriveCmd, servicenowCmd, trelloCmd)
}

// runEnumScan runs the shared enumeration pipeline: load rules → create matcher/store →
// enumerate via the provided enumerator → output results.
// The JSON branch runs BEFORE any human-readable summary lines so that --format json
// produces clean stdout.
func runEnumScan(cmd *cobra.Command, enumerator enum.Enumerator, service string) error {
	switch enumFormat {
	case "human", "json":
	default:
		return fmt.Errorf("unsupported output format %q (expected human or json)", enumFormat)
	}

	rules, err := loadRules(enumRulesPath, enumRulesInclude, enumRulesExclude, enumRuleset, enumIncludeNoisy)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	ruleMap := make(map[string]*types.Rule, len(rules))
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
		Path: enumOutput,
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

	matchCount := 0
	findingCount := 0

	err = enumerator.Enumerate(cmd.Context(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
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
		return fmt.Errorf("scanning %s: %w", service, err)
	}

	// JSON branch runs BEFORE human summary lines so --format json gives clean stdout.
	if enumFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s scan complete: %d matches, %d findings\n", service, matchCount, findingCount)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Results stored in: %s\n", enumOutput)

	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}
	return outputFindings(cmd, findings)
}
