package main

import (
	"fmt"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/spf13/cobra"
)

var rulesCompileCmd = &cobra.Command{
	Use:   "compile",
	Short: "Compile built-in rules for fast scanner startup",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		rules, err := loadRules("", "", "", "all", true)
		if err != nil {
			return fmt.Errorf("load rules: %w", err)
		}
		dir, err := matcher.RulesCacheDir()
		if err != nil {
			return err
		}
		path, err := matcher.WriteHyperscanDatabase(dir, rules)
		if err != nil {
			return fmt.Errorf("compile rules: %w", err)
		}
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), path); err != nil {
			return fmt.Errorf("print compiled rules path: %w", err)
		}
		return nil
	},
}

func init() {
	rulesCmd.AddCommand(rulesCompileCmd)
}
