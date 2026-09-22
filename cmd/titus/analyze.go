package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/scoring"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	analyzeToken        string
	analyzeFile         string
	analyzeType         string
	analyzeFormat       string
	analyzeScoreTimeout time.Duration
	analyzeScoreBudget  time.Duration
	analyzeValidateWorkers int
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze a credential on demand — detect type, validate, score, and enumerate resources",
	Long: `Analyze a specific credential without running a full scan. Titus detects
the credential type, validates it against its source API, scores it with
full dynamic analysis (resource enumeration, owner identification), and
prints a rich analysis report.

Provide the credential via --token, --file, or stdin.`,
	RunE: runAnalyze,
}

func init() {
	analyzeCmd.Flags().StringVar(&analyzeToken, "token", "", "Credential value to analyze")
	analyzeCmd.Flags().StringVar(&analyzeFile, "file", "", "Path to file containing the credential")
	analyzeCmd.Flags().StringVar(&analyzeType, "type", "", "Credential type hint (e.g., aws, github, gitlab) — auto-detected if omitted")
	analyzeCmd.Flags().StringVar(&analyzeFormat, "format", "human", "Output format: human, json")
	analyzeCmd.Flags().DurationVar(&analyzeScoreTimeout, "score-timeout", 10*time.Second, "Timeout per scoring condition")
	analyzeCmd.Flags().DurationVar(&analyzeScoreBudget, "score-budget", 60*time.Second, "Total scoring time budget")
	analyzeCmd.Flags().IntVar(&analyzeValidateWorkers, "validate-workers", 4, "Number of concurrent validation workers")
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	switch analyzeFormat {
	case "json", "human":
	default:
		return fmt.Errorf("unsupported --format %q (supported: human, json)", analyzeFormat)
	}

	input, err := readAnalyzeInput(cmd)
	if err != nil {
		return err
	}
	if len(input) == 0 {
		return fmt.Errorf("no credential provided — use --token, --file, or pipe to stdin")
	}

	rules, ruleMap, err := loadAnalyzeRules()
	if err != nil {
		return err
	}

	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: 0,
		WarnFunc: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	matches, err := m.Match(input)
	if err != nil {
		return fmt.Errorf("matching: %w", err)
	}
	if len(matches) == 0 {
		fmt.Fprintln(os.Stderr, "No credential detected in the provided input.")
		if analyzeType != "" {
			fmt.Fprintf(os.Stderr, "Hint: --type %q was set but no matching rule fired. Check the credential format.\n", analyzeType)
		}
		return nil
	}

	ctx := context.Background()

	valEngine := validator.NewDefaultEngine(analyzeValidateWorkers)
	validateMatches(ctx, valEngine, matches, verbose)

	scorers, err := scoring.AllBuiltinScorers()
	if err != nil {
		return fmt.Errorf("loading scorers: %w", err)
	}
	engine := scoring.NewEngine(scorers, scoring.EngineConfig{
		ScopeEnabled: true,
		Timeout:      analyzeScoreTimeout,
		Budget:       analyzeScoreBudget,
	})

	var results []analyzedFinding
	seen := map[string]bool{}
	for _, match := range matches {
		r, ok := ruleMap[match.RuleID]
		if !ok {
			continue
		}
		findingID := types.ComputeFindingID(r.StructuralID, match.Groups)
		if seen[findingID] {
			continue
		}
		seen[findingID] = true

		f := &types.Finding{
			ID:     findingID,
			RuleID: match.RuleID,
			Groups: match.Groups,
		}
		f.Score = engine.Score(ctx, f, []*types.Match{match}, r)
		results = append(results, analyzedFinding{finding: f, validation: match.ValidationResult})
	}

	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "Matches found but no findings produced.")
		return nil
	}

	switch analyzeFormat {
	case "json":
		return outputAnalyzeJSON(cmd, results, ruleMap)
	default:
		return outputAnalyzeHuman(cmd, results, ruleMap)
	}
}

func readAnalyzeInput(cmd *cobra.Command) ([]byte, error) {
	if analyzeToken != "" {
		return []byte(analyzeToken), nil
	}
	if analyzeFile != "" {
		data, err := os.ReadFile(analyzeFile)
		if err != nil {
			return nil, fmt.Errorf("reading file: %w", err)
		}
		return data, nil
	}
	info, err := os.Stdin.Stat()
	if err != nil {
		return nil, nil
	}
	if (info.Mode() & os.ModeCharDevice) == 0 {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return data, nil
	}
	return nil, nil
}

func loadAnalyzeRules() ([]*types.Rule, map[string]*types.Rule, error) {
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		return nil, nil, fmt.Errorf("loading rules: %w", err)
	}

	if analyzeType != "" {
		var filtered []*types.Rule
		for _, r := range rules {
			if matchesTypeHint(r, analyzeType) {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) == 0 {
			return nil, nil, fmt.Errorf("no rules match --type %q", analyzeType)
		}
		rules = filtered
	}

	ruleMap := make(map[string]*types.Rule, len(rules))
	for _, r := range rules {
		ruleMap[r.ID] = r
	}
	return rules, ruleMap, nil
}

func matchesTypeHint(r *types.Rule, hint string) bool {
	return containsIgnoreCaseAnalyze(r.ID, hint) || containsIgnoreCaseAnalyze(r.Name, hint)
}

func containsIgnoreCaseAnalyze(s, substr string) bool {
	ls, lsub := len(s), len(substr)
	if lsub > ls {
		return false
	}
	for i := 0; i <= ls-lsub; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			t := substr[j]
			if t >= 'A' && t <= 'Z' {
				t += 32
			}
			if c != t {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

type analyzedFinding struct {
	finding    *types.Finding
	validation *types.ValidationResult
}

type analyzeOutput struct {
	Findings []analyzeOutputFinding `json:"findings"`
}

type analyzeOutputFinding struct {
	ID         string                  `json:"id"`
	RuleID     string                  `json:"rule_id"`
	RuleName   string                  `json:"rule_name"`
	Groups     []string                `json:"groups"`
	Validation *types.ValidationResult `json:"validation,omitempty"`
	Score      *types.Score            `json:"score,omitempty"`
	Owner      *types.OwnerInfo        `json:"owner,omitempty"`
	Resources  []types.ResourceInfo    `json:"resources,omitempty"`
}

func outputAnalyzeJSON(cmd *cobra.Command, results []analyzedFinding, ruleMap map[string]*types.Rule) error {
	out := analyzeOutput{}
	for _, af := range results {
		f := af.finding
		ruleName := f.RuleID
		if r, ok := ruleMap[f.RuleID]; ok {
			ruleName = r.Name
		}
		groups := make([]string, len(f.Groups))
		for i, g := range f.Groups {
			groups[i] = string(g)
		}
		out.Findings = append(out.Findings, analyzeOutputFinding{
			ID:         f.ID,
			RuleID:     f.RuleID,
			RuleName:   ruleName,
			Groups:     groups,
			Validation: af.validation,
			Score:      f.Score,
			Owner:      f.Owner,
			Resources:  f.Resources,
		})
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func outputAnalyzeHuman(cmd *cobra.Command, results []analyzedFinding, ruleMap map[string]*types.Rule) error {
	out := cmd.OutOrStdout()

	switch reportColor {
	case "always":
		color.NoColor = false
	case "never":
		color.NoColor = true
	default:
		if !term.IsTerminal(int(os.Stdout.Fd())) || os.Getenv("NO_COLOR") != "" {
			color.NoColor = true
		} else {
			color.NoColor = false
		}
	}
	s := newStyles(!color.NoColor)

	_, _ = fmt.Fprintf(out, "\n%s\n\n",
		s.findingHeading.Sprintf("Credential Analysis — %d finding(s)", len(results)))

	for i, af := range results {
		f := af.finding
		ruleName := f.RuleID
		if r, ok := ruleMap[f.RuleID]; ok {
			ruleName = r.Name
		}

		_, _ = fmt.Fprintf(out, "%s %s\n",
			s.findingHeading.Sprintf("Finding %d/%d", i+1, len(results)),
			s.ruleName.Sprint(ruleName))

		if af.validation != nil {
			valColor := s.metadata
			switch af.validation.Status {
			case "valid":
				valColor = color.New(color.FgHiGreen, color.Bold)
			case "invalid":
				valColor = color.New(color.FgHiRed, color.Bold)
			}
			if color.NoColor {
				valColor.DisableColor()
			}
			valStr := valColor.Sprint(af.validation.Status)
			if af.validation.Message != "" {
				valStr += " — " + s.metadata.Sprint(af.validation.Message)
			}
			_, _ = fmt.Fprintf(out, "  %s %s\n",
				s.heading.Sprint("Validation:"),
				valStr)
		}

		if f.Score != nil {
			severityColor := s.heading
			switch f.Score.SuggestedSeverity {
			case "critical":
				severityColor = color.New(color.FgHiRed, color.Bold)
			case "high":
				severityColor = color.New(color.FgHiYellow, color.Bold)
			case "medium":
				severityColor = color.New(color.FgHiBlue)
			case "low", "info":
				severityColor = color.New(color.Faint)
			}
			if color.NoColor {
				severityColor.DisableColor()
			}
			_, _ = fmt.Fprintf(out, "  %s %d/100 (%s)\n",
				s.heading.Sprint("Score:"),
				f.Score.Final,
				severityColor.Sprint(f.Score.SuggestedSeverity))
		}

		if f.Owner != nil {
			ownerStr := f.Owner.User
			if f.Owner.Email != "" && f.Owner.Email != f.Owner.User {
				ownerStr += " (" + f.Owner.Email + ")"
			}
			if f.Owner.AccountID != "" {
				ownerStr += " [" + f.Owner.AccountID + "]"
			}
			_, _ = fmt.Fprintf(out, "  %s %s\n",
				s.heading.Sprint("Owner:"),
				s.metadata.Sprint(ownerStr))
		}

		if len(f.Resources) > 0 {
			_, _ = fmt.Fprintf(out, "  %s %s\n",
				s.heading.Sprint("Resources:"),
				s.metadata.Sprint(formatResourceSummary(f.Resources)))
			for _, r := range f.Resources {
				detail := r.Type + ": " + r.Name
				if r.Count > 0 {
					detail = fmt.Sprintf("%s: %d", r.Type, r.Count)
					if r.Name != "" {
						detail += " (" + r.Name + ")"
					}
				}
				if r.Region != "" {
					detail += " [" + r.Region + "]"
				}
				_, _ = fmt.Fprintf(out, "    %s\n", s.metadata.Sprint(detail))
			}
		}

		for j, group := range f.Groups {
			_, _ = fmt.Fprintf(out, "  %s %s\n",
				s.heading.Sprintf("Group %d:", j+1),
				s.match.Sprint(string(group)))
		}

		if f.Score != nil && len(f.Score.Applied) > 0 {
			_, _ = fmt.Fprintf(out, "  %s\n", s.heading.Sprint("Scoring trail:"))
			for _, mod := range f.Score.Applied {
				_, _ = fmt.Fprintf(out, "    %s %s %s=%d (priority %d)\n",
					s.metadata.Sprint(mod.Scorer),
					s.metadata.Sprint(mod.Name),
					mod.Kind,
					mod.Value,
					mod.Priority)
			}
		}

		_, _ = fmt.Fprintf(out, "\n")
	}

	return nil
}
