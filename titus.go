// Package titus provides a high-performance secrets detection library.
//
// Titus is a Go port of NoseyParker that can scan content for secrets
// such as API keys, tokens, passwords, and other sensitive credentials.
//
// # Basic Usage
//
// Create a scanner with builtin rules and scan content:
//
//	scanner, err := titus.NewScanner()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer scanner.Close()
//
//	matches, err := scanner.ScanString("aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, match := range matches {
//	    fmt.Printf("Found %s at offset %d\n", match.RuleName, match.Location.Offset.Start)
//	}
//
// # With Validation
//
// Enable validation to check if detected secrets are active:
//
//	scanner, err := titus.NewScanner(titus.WithValidation())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer scanner.Close()
//
//	matches, err := scanner.ScanString(content)
//	for _, match := range matches {
//	    if match.ValidationResult != nil {
//	        fmt.Printf("%s: %s\n", match.RuleName, match.ValidationResult.Status)
//	    }
//	}
package titus

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
)

// Re-export commonly used types for convenience.
// Users can import just "github.com/praetorian-inc/titus" without subpackages.
type (
	// Match represents a single secret detection result.
	Match = types.Match

	// Rule defines a detection pattern for a specific secret type.
	Rule = types.Rule

	// ValidationResult contains the outcome of validating a detected secret.
	ValidationResult = types.ValidationResult

	// ValidationStatus indicates whether a secret is valid, invalid, or undetermined.
	ValidationStatus = types.ValidationStatus

	// Location describes where a match was found within content.
	Location = types.Location

	// Snippet contains the matched text with surrounding context.
	Snippet = types.Snippet
)

// Re-export validation status constants.
const (
	StatusValid        = types.StatusValid
	StatusInvalid      = types.StatusInvalid
	StatusUndetermined = types.StatusUndetermined
)

// Scanner provides secret detection capabilities.
type Scanner struct {
	matcher          matcher.Matcher
	validationEngine *validator.Engine
	config           *scannerConfig
	mu               sync.RWMutex
}

// scannerConfig holds scanner configuration.
type scannerConfig struct {
	rules            []*types.Rule
	contextLines     int
	enableValidation bool
	validationWorkers int
}

// Option configures a Scanner.
type Option func(*scannerConfig)

// WithRules uses custom rules instead of builtin rules.
// If not specified, the scanner uses all 444+ builtin detection rules.
func WithRules(rules []*Rule) Option {
	return func(c *scannerConfig) {
		c.rules = rules
	}
}

// WithContextLines sets the number of context lines to include around matches.
// Default is 2 lines before and after.
func WithContextLines(lines int) Option {
	return func(c *scannerConfig) {
		c.contextLines = lines
	}
}

// WithValidation enables secret validation.
// When enabled, detected secrets are checked against their source APIs
// to determine if they are still active/valid.
func WithValidation() Option {
	return func(c *scannerConfig) {
		c.enableValidation = true
	}
}

// WithValidationWorkers sets the number of concurrent validation workers.
// Default is 4. Only applies when validation is enabled.
func WithValidationWorkers(workers int) Option {
	return func(c *scannerConfig) {
		c.validationWorkers = workers
	}
}

// NewScanner creates a new Scanner with the given options.
//
// By default, the scanner:
//   - Uses all builtin detection rules (444+ rules)
//   - Includes 2 lines of context around matches
//   - Does NOT validate secrets (enable with WithValidation)
//
// Example:
//
//	// Default scanner
//	scanner, err := titus.NewScanner()
//
//	// With validation enabled
//	scanner, err := titus.NewScanner(titus.WithValidation())
//
//	// With custom rules
//	scanner, err := titus.NewScanner(titus.WithRules(myRules))
func NewScanner(opts ...Option) (*Scanner, error) {
	config := &scannerConfig{
		contextLines:      2,
		validationWorkers: 4,
	}

	for _, opt := range opts {
		opt(config)
	}

	// Load rules if not provided
	if config.rules == nil {
		loader := rule.NewLoader()
		rules, err := loader.LoadBuiltinRules()
		if err != nil {
			return nil, fmt.Errorf("loading builtin rules: %w", err)
		}
		config.rules = rules
	}

	// Create matcher
	m, err := matcher.New(matcher.Config{
		Rules:        config.rules,
		ContextLines: config.contextLines,
	})
	if err != nil {
		return nil, fmt.Errorf("creating matcher: %w", err)
	}

	// Create validation engine if enabled
	var validationEngine *validator.Engine
	if config.enableValidation {
		validationEngine = createValidationEngine(config.validationWorkers)
	}

	return &Scanner{
		matcher:          m,
		validationEngine: validationEngine,
		config:           config,
	}, nil
}

// ScanString scans a string for secrets and returns all matches.
//
// Example:
//
//	matches, err := scanner.ScanString("aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
//	if err != nil {
//	    return err
//	}
//	for _, match := range matches {
//	    fmt.Printf("Found: %s\n", match.RuleName)
//	}
func (s *Scanner) ScanString(content string) ([]*Match, error) {
	return s.ScanBytes([]byte(content))
}

// ScanBytes scans raw bytes for secrets and returns all matches.
func (s *Scanner) ScanBytes(content []byte) ([]*Match, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	matches, err := s.matcher.Match(content)
	if err != nil {
		return nil, err
	}

	// Validate matches if enabled
	if s.validationEngine != nil && len(matches) > 0 {
		s.validateMatches(context.Background(), matches)
	}

	return matches, nil
}

// ScanFile reads and scans a file for secrets.
//
// Example:
//
//	matches, err := scanner.ScanFile("/path/to/config.json")
func (s *Scanner) ScanFile(path string) ([]*Match, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return s.ScanBytes(content)
}

// ScanStringWithContext scans content with a custom context for validation cancellation.
func (s *Scanner) ScanStringWithContext(ctx context.Context, content string) ([]*Match, error) {
	return s.ScanBytesWithContext(ctx, []byte(content))
}

// ScanBytesWithContext scans raw bytes with a custom context for validation cancellation.
func (s *Scanner) ScanBytesWithContext(ctx context.Context, content []byte) ([]*Match, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	matches, err := s.matcher.Match(content)
	if err != nil {
		return nil, err
	}

	// Validate matches if enabled
	if s.validationEngine != nil && len(matches) > 0 {
		s.validateMatches(ctx, matches)
	}

	return matches, nil
}

// Close releases scanner resources.
// Always call Close when done with the scanner.
func (s *Scanner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.matcher != nil {
		s.matcher.Close()
	}
	return nil
}

// RuleCount returns the number of detection rules loaded.
func (s *Scanner) RuleCount() int {
	return len(s.config.rules)
}

// Rules returns a copy of the loaded detection rules.
func (s *Scanner) Rules() []*Rule {
	rules := make([]*Rule, len(s.config.rules))
	copy(rules, s.config.rules)
	return rules
}

// ValidationEnabled returns whether secret validation is enabled.
func (s *Scanner) ValidationEnabled() bool {
	return s.validationEngine != nil
}

// validateMatches validates matches using the validation engine.
func (s *Scanner) validateMatches(ctx context.Context, matches []*Match) {
	if s.validationEngine == nil || len(matches) == 0 {
		return
	}

	// Submit all matches for async validation
	results := make([]<-chan *types.ValidationResult, len(matches))
	for i := range matches {
		results[i] = s.validationEngine.ValidateAsync(ctx, matches[i])
	}

	// Wait for all validations and attach results
	for i, ch := range results {
		result := <-ch
		matches[i].ValidationResult = result
	}
}

// createValidationEngine creates a validation engine with all available validators.
func createValidationEngine(workers int) *validator.Engine {
	var validators []validator.Validator

	// Add Go validators (complex multi-credential validation)
	validators = append(validators, validator.NewAWSValidator())
	validators = append(validators, validator.NewSauceLabsValidator())
	validators = append(validators, validator.NewTwilioValidator())
	validators = append(validators, validator.NewAzureStorageValidator())
	validators = append(validators, validator.NewPostgresValidator())

	// Add embedded YAML validators
	embedded, err := validator.LoadEmbeddedValidators()
	if err == nil {
		validators = append(validators, embedded...)
	}

	return validator.NewEngine(workers, validators...)
}

// LoadRulesFromFile loads detection rules from a YAML file.
// Use this with WithRules to create a scanner with custom rules.
//
// Example:
//
//	rules, err := titus.LoadRulesFromFile("/path/to/rules.yaml")
//	if err != nil {
//	    return err
//	}
//	scanner, err := titus.NewScanner(titus.WithRules(rules))
func LoadRulesFromFile(path string) ([]*Rule, error) {
	loader := rule.NewLoader()
	r, err := loader.LoadRuleFile(path)
	if err != nil {
		return nil, err
	}
	return []*Rule{r}, nil
}

// LoadBuiltinRules returns all builtin detection rules.
// This can be used to inspect available rules or create a subset.
//
// Example:
//
//	rules, err := titus.LoadBuiltinRules()
//	if err != nil {
//	    return err
//	}
//
//	// Filter to only AWS rules
//	var awsRules []*titus.Rule
//	for _, r := range rules {
//	    if strings.HasPrefix(r.ID, "np.aws") {
//	        awsRules = append(awsRules, r)
//	    }
//	}
//	scanner, err := titus.NewScanner(titus.WithRules(awsRules))
func LoadBuiltinRules() ([]*Rule, error) {
	loader := rule.NewLoader()
	return loader.LoadBuiltinRules()
}
