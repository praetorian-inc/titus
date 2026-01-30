package scanner

import (
	"encoding/json"
	"sync"

	"github.com/praetorian-inc/titus/pkg/matcher"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

var (
	// cachedBuiltinRules holds builtin rules loaded once per process
	cachedBuiltinRules []*types.Rule
	cachedRulesErr     error
	cacheOnce          sync.Once
)

// loadBuiltinRulesCached loads builtin rules once and caches them
func loadBuiltinRulesCached() ([]*types.Rule, error) {
	cacheOnce.Do(func() {
		loader := rule.NewLoader()
		cachedBuiltinRules, cachedRulesErr = loader.LoadBuiltinRules()
	})
	return cachedBuiltinRules, cachedRulesErr
}

// Core wraps the matcher and store for scanning operations
type Core struct {
	matcher matcher.Matcher
	store   store.Store
	logger  DebugLogger
}

// NewCore creates a new Core scanner with the given rules
// rulesJSON can be:
// - "" or "builtin" to load builtin rules (cached)
// - JSON string with custom rules array
func NewCore(rulesJSON string, logger DebugLogger) (*Core, error) {
	if logger == nil {
		logger = NoopLogger{}
	}

	logger.Log("NewCore starting...")

	// Parse or load rules
	var rules []*types.Rule
	if rulesJSON == "" || rulesJSON == "builtin" {
		logger.Log("Loading builtin rules (cached)...")
		var err error
		rules, err = loadBuiltinRulesCached()
		if err != nil {
			logger.Log("loadBuiltinRulesCached failed: %v", err)
			return nil, err
		}
		logger.Log("Loaded %d builtin rules", len(rules))
	} else {
		logger.Log("Parsing custom rules JSON...")
		if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
			logger.Log("JSON unmarshal failed: %v", err)
			return nil, err
		}
		logger.Log("Parsed %d custom rules", len(rules))
	}

	// Create matcher
	logger.Log("Creating matcher with %d rules...", len(rules))
	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: 2,
	})
	if err != nil {
		logger.Log("matcher.New failed: %v", err)
		return nil, err
	}
	logger.Log("Matcher created successfully")

	// Create in-memory store
	logger.Log("Creating store...")
	s, err := store.New(store.Config{Path: ":memory:"})
	if err != nil {
		logger.Log("store.New failed: %v", err)
		m.Close()
		return nil, err
	}
	logger.Log("Store created successfully")

	logger.Log("NewCore complete")
	return &Core{
		matcher: m,
		store:   s,
		logger:  logger,
	}, nil
}

// Scan scans a single content string
func (c *Core) Scan(content, source string) (*ScanResult, error) {
	matches, err := c.matcher.Match([]byte(content))
	if err != nil {
		return nil, err
	}

	// Store matches
	for _, match := range matches {
		c.store.AddMatch(match)
	}

	return &ScanResult{
		Source:  source,
		Matches: matches,
	}, nil
}

// ScanBatch scans multiple content items
func (c *Core) ScanBatch(items []ContentItem) (*BatchScanResult, error) {
	var results []ScanResult
	total := 0

	for _, item := range items {
		matches, err := c.matcher.Match([]byte(item.Content))
		if err != nil {
			// Skip items that fail to scan
			continue
		}

		// Store matches
		for _, match := range matches {
			c.store.AddMatch(match)
		}

		results = append(results, ScanResult{
			Source:  item.Source,
			Matches: matches,
		})
		total += len(matches)
	}

	return &BatchScanResult{
		Results: results,
		Total:   total,
	}, nil
}

// Close releases scanner resources
func (c *Core) Close() {
	if c.matcher != nil {
		c.matcher.Close()
	}
	if c.store != nil {
		c.store.Close()
	}
}

// GetBuiltinRules returns the built-in rules (cached)
func GetBuiltinRules() ([]*types.Rule, error) {
	return loadBuiltinRulesCached()
}
