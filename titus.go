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
//
// # With Scoring
//
// Enable rule-based severity scoring with optional accessibility adjustment:
//
//	scanner, err := titus.NewScanner(
//	    titus.WithScoring(),
//	    titus.WithAccessibility(titus.AccessibilityPrivate),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer scanner.Close()
//
//	findings, err := scanner.ScanBytesWithFindings(ctx, content)
//	for _, f := range findings {
//	    fmt.Printf("Rule %s score %d (%s)\n", f.RuleID, f.Score.Final, f.Score.SuggestedSeverity)
//	}
package titus

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/praetorian-inc/titus/pkg/accessibility"
	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/scoring"
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

	// Finding groups deduplicated matches by (rule, secret-groups) key.
	// Each Finding has a populated Score when WithScoring() is used.
	Finding = types.Finding

	// Score captures a finding's computed severity and the modifiers applied.
	Score = types.Score

	// ScoreModifier records a single modifier that fired during scoring.
	ScoreModifier = types.ScoreModifier
)

// Re-export validation status constants.
const (
	StatusValid        = types.StatusValid
	StatusInvalid      = types.StatusInvalid
	StatusUndetermined = types.StatusUndetermined
)

// Accessibility mode constants control how private-code score adjustments are applied.
const (
	// AccessibilityPublic means the code is world-readable; no score penalty.
	AccessibilityPublic = "public"
	// AccessibilityPrivate means the code is not world-readable; -25 to all scores.
	AccessibilityPrivate = "private"
	// AccessibilityAuto means detect from git remote; defaults to Private on failure.
	AccessibilityAuto = "auto"
)

// Scanner provides secret detection capabilities.
type Scanner struct {
	matcher          matcher.Matcher
	validationEngine *validator.Engine
	scoringEngine    *scoring.Engine    // nil when scoring disabled
	resolvedAccess   accessibility.Accessibility // resolved once in NewScanner
	config           *scannerConfig
	mu               sync.RWMutex
}

// scannerConfig holds scanner configuration.
type scannerConfig struct {
	rules             []*types.Rule
	contextLines      int
	enableValidation  bool
	validationWorkers int
	// Scoring fields (M2)
	enableScoring bool
	// Scope fields (M3)
	scopeEnabled bool
	scopeTimeout time.Duration
	scopeBudget  time.Duration
	// Accessibility fields
	accessibility       string // "public", "private", "auto"
	accessibilityTarget string // for auto-detection: git repo root path
	scmToken            string // for auto-detection: SCM API token (GitHub, GitLab, or Bitbucket)
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

// WithScoring enables rule-based severity scoring. Each finding returned by
// ScanBytesWithFindings / ScanStringWithFindings / ScanFileWithFindings will
// have a populated Score field with Base, Final, SuggestedSeverity, and Applied.
func WithScoring() Option {
	return func(c *scannerConfig) { c.enableScoring = true }
}

// WithScopeEnabled enables HTTP dynamic scoring modifiers (M3). When true,
// configured scorer YAML files will make API calls to determine a secret's
// actual scope and permissions before finalising its score.
// Has no effect unless WithScoring() is also applied.
func WithScopeEnabled(enabled bool) Option {
	return func(c *scannerConfig) { c.scopeEnabled = enabled }
}

// WithScopeTimeout sets the per-modifier HTTP deadline for dynamic scoring.
// Defaults to 10s. Has no effect unless WithScopeEnabled(true) is applied.
func WithScopeTimeout(d time.Duration) Option {
	return func(c *scannerConfig) { c.scopeTimeout = d }
}

// WithScopeBudget sets the per-finding overall scoring budget across all
// modifiers. Zero means no cap. Defaults to 60s.
func WithScopeBudget(d time.Duration) Option {
	return func(c *scannerConfig) { c.scopeBudget = d }
}

// WithAccessibility sets the code-accessibility mode for score adjustment.
// Accepted values: AccessibilityPublic, AccessibilityPrivate, AccessibilityAuto.
// Private code receives a -25 score penalty on all findings.
// Auto-detection inspects the git remote of target (set via WithAccessibilityTarget)
// and calls the appropriate SCM API with the token set via WithSCMToken.
// Defaults to no accessibility adjustment (same as not calling this option).
func WithAccessibility(mode string) Option {
	return func(c *scannerConfig) { c.accessibility = mode }
}

// WithAccessibilityTarget sets the filesystem path used for git remote detection
// when WithAccessibility(AccessibilityAuto) is configured.
func WithAccessibilityTarget(target string) Option {
	return func(c *scannerConfig) { c.accessibilityTarget = target }
}

// WithSCMToken sets the SCM API token used for repository visibility detection
// when WithAccessibility(AccessibilityAuto) is configured. The token is forwarded
// to whichever SCM platform matches the git remote URL:
//   - GitHub: sent as Authorization: Bearer {token}
//   - GitLab: sent as PRIVATE-TOKEN: {token}
//   - Bitbucket: sent as Authorization: Bearer {token}
//
// Each platform also accepts a platform-specific environment variable as a
// fallback (GITHUB_TOKEN, GITLAB_TOKEN, BITBUCKET_TOKEN) when no token is
// supplied via this option.
func WithSCMToken(token string) Option {
	return func(c *scannerConfig) { c.scmToken = token }
}

// NewScanner creates a new Scanner with the given options.
//
// By default, the scanner:
//   - Uses all builtin detection rules (444+ rules)
//   - Includes 2 lines of context around matches
//   - Does NOT validate secrets (enable with WithValidation)
//   - Does NOT score findings (enable with WithScoring)
//
// Example:
//
//	// Default scanner
//	scanner, err := titus.NewScanner()
//
//	// With validation enabled
//	scanner, err := titus.NewScanner(titus.WithValidation())
//
//	// With scoring and private-code adjustment
//	scanner, err := titus.NewScanner(
//	    titus.WithScoring(),
//	    titus.WithAccessibility(titus.AccessibilityPrivate),
//	)
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

	// Initialize scoring engine if enabled
	var scoringEngine *scoring.Engine
	if config.enableScoring {
		loader := scoring.NewLoader()
		scorers, err := loader.LoadBuiltinScorers()
		if err != nil {
			return nil, fmt.Errorf("loading scorers: %w", err)
		}
		cfg := scoring.EngineConfig{
			ScopeEnabled: config.scopeEnabled,
			Timeout:      config.scopeTimeout,
			Budget:       config.scopeBudget,
		}
		scoringEngine = scoring.NewEngine(scorers, cfg)
	}

	// Resolve accessibility once at construction time
	var resolvedAccess accessibility.Accessibility
	if config.accessibility != "" {
		resolvedAccess = accessibility.Resolve(
			config.accessibility,
			config.accessibilityTarget,
			config.scmToken,
		)
	}

	return &Scanner{
		matcher:          m,
		validationEngine: validationEngine,
		scoringEngine:    scoringEngine,
		resolvedAccess:   resolvedAccess,
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

// ScanBytesWithFindings scans content and returns deduplicated findings with
// scoring. Requires WithScoring() to be applied for Score fields to be populated.
func (s *Scanner) ScanBytesWithFindings(ctx context.Context, content []byte) ([]*Finding, error) {
	matches, err := s.ScanBytesWithContext(ctx, content)
	if err != nil {
		return nil, err
	}
	return s.matchesToFindings(ctx, matches)
}

// ScanStringWithFindings scans a string and returns deduplicated findings.
func (s *Scanner) ScanStringWithFindings(ctx context.Context, content string) ([]*Finding, error) {
	return s.ScanBytesWithFindings(ctx, []byte(content))
}

// ScanFileWithFindings scans a file and returns deduplicated findings.
func (s *Scanner) ScanFileWithFindings(ctx context.Context, path string) ([]*Finding, error) {
	// #nosec G304 -- path is supplied by the library caller who controls which
	// files to scan; reading caller-supplied paths is the intended purpose of
	// this API, matching the existing ScanFile behaviour.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return s.ScanBytesWithFindings(ctx, data)
}

// Close releases scanner resources.
// Always call Close when done with the scanner.
func (s *Scanner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.matcher != nil {
		_ = s.matcher.Close()
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

// ScoringEnabled returns whether scoring is enabled.
func (s *Scanner) ScoringEnabled() bool {
	return s.scoringEngine != nil
}

// matchesToFindings converts a flat list of matches into deduplicated findings,
// applying scoring and accessibility modifiers when configured.
func (s *Scanner) matchesToFindings(ctx context.Context, matches []*Match) ([]*Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build rule map from the scanner's pre-loaded rules.
	// StructuralID is computed at load time for builtin rules; for user-provided
	// rules that may not have it set, we compute it on demand.
	ruleMap := make(map[string]*types.Rule, len(s.config.rules))
	for _, r := range s.config.rules {
		if r.StructuralID == "" {
			r.StructuralID = r.ComputeStructuralID()
		}
		ruleMap[r.ID] = r
	}

	// Deduplicate matches into findings by (rule_structural_id, groups).
	findingsByID := make(map[string]*Finding)
	var findingOrder []string // preserve insertion order

	for _, m := range matches {
		r, ok := ruleMap[m.RuleID]
		if !ok {
			continue
		}
		fid := types.ComputeFindingID(r.StructuralID, m.Groups)
		if _, exists := findingsByID[fid]; !exists {
			f := &Finding{
				ID:     fid,
				RuleID: m.RuleID,
				Groups: m.Groups,
			}
			// Apply scoring if engine is present
			if s.scoringEngine != nil {
				f.Score = s.scoringEngine.Score(ctx, f, []*Match{m}, r)
				// Apply accessibility modifier if configured
				if s.config.accessibility != "" && s.resolvedAccess == accessibility.Private {
					accessibility.Apply(f.Score)
				}
			}
			findingsByID[fid] = f
			findingOrder = append(findingOrder, fid)
		}
		findingsByID[fid].Matches = append(findingsByID[fid].Matches, m)
	}

	findings := make([]*Finding, 0, len(findingOrder))
	for _, id := range findingOrder {
		findings = append(findings, findingsByID[id])
	}
	return findings, nil
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
	return validator.NewDefaultEngine(workers)
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

// verify-claude-fix: trivial no-op comment to exercise the claude reviewer pipeline (PR not for merge)
