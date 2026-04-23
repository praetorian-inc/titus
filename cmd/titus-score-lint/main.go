// Command titus-score-lint validates that every rule YAML under the given
// rules directory has a base_score in [0, 100] and flags obvious mis-tierings.
//
// Usage:
//
//	titus-score-lint <rules-dir>
//
// Exits 0 on success, non-zero if any violations are found.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// yamlRuleMinimal is a lightweight struct for parsing rule YAML without
// importing the full rule package. This lets the linter work on arbitrary
// directories, not just the embedded filesystem.
type yamlRuleMinimal struct {
	ID        string `yaml:"id"`
	BaseScore *int   `yaml:"base_score"`
}

type yamlRulesFileMinimal struct {
	Rules []yamlRuleMinimal `yaml:"rules"`
}

// namingRule describes a naming-tier requirement: if the rule ID contains
// idContains, its base_score must be at least minScore.
type namingRule struct {
	idContains string
	minScore   int
	reason     string
}

// namingRules is the set of soft naming-tier checks (lint warnings, not hard errors).
// Use specific rule ID substrings — broad prefixes (e.g. "np.aws.") are avoided
// because some rules in a family legitimately score lower (public identifiers,
// test keys, read-only tokens).
var namingRules = []namingRule{
	{idContains: "np.aws.2", minScore: 60, reason: "AWS Secret Access Key should be tier high or above"},
	{idContains: "np.aws.6", minScore: 60, reason: "AWS API Credentials should be tier high or above"},
	{idContains: "np.pem.", minScore: 80, reason: "PEM private keys are tier critical"},
	{idContains: "np.stripe.1", minScore: 80, reason: "Stripe live API keys move money — tier critical"},
}

// lintDir walks dir and validates every .yml file's rules for base_score.
// Returns a slice of human-readable violation strings (empty means clean).
func lintDir(dir string) []string {
	var errs []string

	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, path+": walk error: "+err.Error())
			return nil
		}
		if d.IsDir() || filepath.Ext(path) != ".yml" {
			return nil
		}

		// #nosec G304 -- path comes from filepath.WalkDir under the rules-dir CLI argument; dev-only lint tool.
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			errs = append(errs, path+": read error: "+readErr.Error())
			return nil
		}

		var rulesFile yamlRulesFileMinimal
		if parseErr := yaml.Unmarshal(data, &rulesFile); parseErr != nil {
			errs = append(errs, path+": yaml parse error: "+parseErr.Error())
			return nil
		}

		for _, r := range rulesFile.Rules {
			// Check required field.
			if r.BaseScore == nil {
				errs = append(errs, fmt.Sprintf("%s [%s]: base_score is missing (required)", r.ID, path))
				continue
			}

			score := *r.BaseScore

			// Check range.
			if score < 0 || score > 100 {
				errs = append(errs, fmt.Sprintf("%s [%s]: base_score=%d out of range [0, 100]",
					r.ID, path, score))
				continue
			}

			// Check naming-tier rules.
			for _, nr := range namingRules {
				if strings.Contains(r.ID, nr.idContains) && score < nr.minScore {
					errs = append(errs, fmt.Sprintf(
						"%s [%s]: base_score=%d — naming suggests minimum %d (%s)",
						r.ID, path, score, nr.minScore, nr.reason))
				}
			}
		}

		return nil
	})

	if walkErr != nil {
		errs = append(errs, "walk error: "+walkErr.Error())
	}

	return errs
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: titus-score-lint <rules-dir>")
		os.Exit(2)
	}

	dir := os.Args[1]
	errs := lintDir(dir)

	for _, e := range errs {
		fmt.Fprintln(os.Stderr, e)
	}

	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d violation(s)\n", len(errs))
		os.Exit(1)
	}

	fmt.Println("score-lint: all rules valid")
}
