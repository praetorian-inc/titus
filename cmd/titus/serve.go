package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/praetorian-inc/titus/pkg/scanner"
	"github.com/praetorian-inc/titus/pkg/serve"
	"github.com/praetorian-inc/titus/pkg/validator"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run as streaming server for Burp extension integration",
	Long: `Run Titus as a long-lived streaming server that accepts scan requests
via stdin and outputs findings via stdout using NDJSON format.

This mode is designed for integration with the Burp Suite extension.
The process loads rules once at startup and processes requests until
stdin closes or SIGTERM is received.`,
	RunE: runServe,
}

var (
	serveRulesPath    string
	serveRulesInclude string
	serveRulesExclude string
	serveRuleset      string
	serveIncludeNoisy bool
)

func init() {
	serveCmd.Flags().StringVar(&serveRulesPath, "rules", "", "Path to custom rules file or directory")
	serveCmd.Flags().StringVar(&serveRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	serveCmd.Flags().StringVar(&serveRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	serveCmd.Flags().StringVar(&serveRuleset, "ruleset", "all", "Ruleset to use: default, np.assets, np.hashes, all (all = no filtering)")
	serveCmd.Flags().BoolVar(&serveIncludeNoisy, "include-noisy", true, "Enable rules marked noisy: true (high false-positive rate)")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	rules, err := loadRules(serveRulesPath, serveRulesInclude, serveRulesExclude, serveRuleset, serveIncludeNoisy)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	core, err := scanner.NewCoreWithRules(rules, nil, func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format, args...)
	})
	if err != nil {
		return err
	}
	defer core.Close()

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigChan
		cancel()
	}()

	// Create and run server
	srv := serve.NewServer(core, cmd.InOrStdin(), cmd.OutOrStdout())
	srv.SetValidator(initServeValidators())
	return srv.Run(ctx)
}

func initServeValidators() *validator.Engine {
	var validators []validator.Validator

	// Add Go validators
	validators = append(validators, validator.NewAWSValidator())
	validators = append(validators, validator.NewSauceLabsValidator())
	validators = append(validators, validator.NewTwilioValidator())
	validators = append(validators, validator.NewAzureStorageValidator())
	validators = append(validators, validator.NewPostgresValidator())

	// Add embedded YAML validators
	embedded, err := validator.LoadEmbeddedValidators()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to load embedded validators: %v\n", err)
	} else {
		validators = append(validators, embedded...)
	}

	return validator.NewEngine(4, validators...)
}
