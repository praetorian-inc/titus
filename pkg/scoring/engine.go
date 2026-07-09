package scoring

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

// EngineConfig controls Engine behavior. Zero value gives safe defaults.
type EngineConfig struct {
	// ScopeEnabled enables HTTP dynamic modifiers. When false, only static
	// modifiers run (the M2 behavior). Default: false.
	ScopeEnabled bool
	// Timeout is the per-modifier HTTP deadline. 0 means use 10s default.
	Timeout time.Duration
	// Budget is the per-finding overall scoring deadline across ALL modifiers.
	// 0 means no per-finding cap (unlimited).
	Budget time.Duration
	// WarnF is a printf-style logging function. Nil defaults to stderr.
	WarnF func(format string, args ...any)
}

const defaultModifierTimeout = 10 * time.Second

// Engine applies modifiers to findings. Construct once per scan.
type Engine struct {
	scorers []*Scorer
	cfg     EngineConfig
	// warnf is pluggable for tests; defaults to stderr logging to match the
	// matcher's warning style (cmd/titus/scan.go).
	warnf func(format string, args ...any)
	stats   HTTPModifierStats // aggregate HTTP modifier outcomes
	statsMu sync.Mutex        // protects stats from concurrent Score() callers
	cache   *httpResponseCache // per-scan shared HTTP response cache
}

// NewEngine constructs an Engine. Passing nil scorers gives a base-only engine.
func NewEngine(scorers []*Scorer, cfg EngineConfig) *Engine {
	warnf := cfg.WarnF
	if warnf == nil {
		warnf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format, args...) }
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultModifierTimeout
	}
	return &Engine{scorers: scorers, cfg: cfg, warnf: warnf, cache: newHTTPResponseCache()}
}

// Score computes the finding's score. It never returns an error — condition
// evaluation errors are logged as warnings and the offending modifier is
// skipped. Order of operations:
//
//  1. Find the first scorer whose RuleIDs contains rule.ID (or base-only).
//  2. Sort modifiers by priority DESC, YAML declaration order ASC on ties.
//  3. Inject shared HTTP cache into all httpConditions.
//  4. Skip dynamic modifiers when cfg.ScopeEnabled is false.
//  5. Evaluate each modifier's condition against the primary match.
//  6. Apply action (delta accumulates, set_score replaces).
//  7. Clamp final to [0, 100], recompute SuggestedSeverity.
//
// ctx carries the scan-level deadline; Score further constrains it with
// per-finding budget and per-modifier timeout sub-contexts.
func (e *Engine) Score(ctx context.Context, f *types.Finding, matches []*types.Match, rule *types.Rule) *types.Score {
	score := &types.Score{
		Final:             rule.BaseScore,
		Base:              rule.BaseScore,
		SuggestedSeverity: types.SeverityForScore(rule.BaseScore),
		Applied:           []types.ScoreModifier{},
	}
	scorer := e.findScorer(f.RuleID)
	if scorer == nil || len(scorer.Modifiers) == 0 {
		return score
	}

	var primary *types.Match
	if len(matches) > 0 {
		primary = matches[0]
	}

	// Apply per-finding budget as a context deadline.
	findingCtx := ctx
	var cancel context.CancelFunc
	if e.cfg.Budget > 0 {
		findingCtx, cancel = context.WithTimeout(ctx, e.cfg.Budget)
		defer cancel()
	}

	// Priority DESC, YAML-ASC on ties. Make a stable copy to preserve
	// declaration order for tie-breaking.
	ordered := make([]indexedModifier, len(scorer.Modifiers))
	for i, m := range scorer.Modifiers {
		ordered[i] = indexedModifier{mod: m, yamlIdx: i}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].mod.Priority != ordered[j].mod.Priority {
			return ordered[i].mod.Priority > ordered[j].mod.Priority
		}
		return ordered[i].yamlIdx < ordered[j].yamlIdx
	})

	current := score.Final
	for _, im := range ordered {
		m := im.mod

		// Skip dynamic modifiers when scope is not enabled.
		if m.IsDynamic() && !e.cfg.ScopeEnabled {
			continue
		}

		// Per-modifier timeout sub-context.
		modCtx, modCancel := context.WithTimeout(findingCtx, e.cfg.Timeout)
		var fired bool
		var err error
		if hc, ok := m.Condition.(*httpCondition); ok {
			// Use evaluateWithCache to pass the engine's shared cache without
			// mutating the shared *httpCondition.cache field (race fix).
			fired, err = hc.evaluateWithCache(modCtx, primary, e.cache)
		} else {
			fired, err = m.Condition.Evaluate(modCtx, primary)
		}
		modCancel()

		if err != nil {
			e.warnf("[warn] scorer %q modifier %q: %v (skipping)\n", scorer.Name, m.Name, err)
			e.trackError(err)
			continue
		}
		if !fired {
			continue
		}

		switch m.Kind {
		case ModifierKindDelta:
			current += m.Value
		case ModifierKindSetScore:
			current = m.Value
		default:
			e.warnf("[warn] scorer %q modifier %q: unknown kind %q (skipping)\n", scorer.Name, m.Name, m.Kind)
			continue
		}
		score.Applied = append(score.Applied, types.ScoreModifier{
			Name:     m.Name,
			Scorer:   scorer.Name,
			Kind:     string(m.Kind),
			Value:    m.Value,
			Priority: m.Priority,
		})
	}

	// Clamp ONCE at the end.
	if current < 0 {
		current = 0
	}
	if current > 100 {
		current = 100
	}
	score.Final = current
	score.SuggestedSeverity = types.SeverityForScore(current)
	return score
}

// trackError increments the relevant stats counter based on error type.
// It is safe to call concurrently from multiple Score() goroutines.
func (e *Engine) trackError(err error) {
	e.statsMu.Lock()
	defer e.statsMu.Unlock()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		e.stats.Timeouts++
	case errors.Is(err, ErrModifierRateLimit):
		e.stats.RateLimited++
	case errors.Is(err, ErrModifierServerError):
		e.stats.ServerErrors++
	case errors.Is(err, ErrModifierNetwork):
		e.stats.NetworkErrors++
	}
}

// Stats returns aggregate HTTP modifier outcomes for the scan stats line.
// Safe to call after all Score() goroutines have completed.
func (e *Engine) Stats() HTTPModifierStats {
	e.statsMu.Lock()
	defer e.statsMu.Unlock()
	return e.stats
}

// Reset clears the per-scan HTTP response cache and stats so a reused engine
// never carries one scan's fetched responses or counters into another.
func (e *Engine) Reset() {
	e.cache.clear()
	e.statsMu.Lock()
	e.stats = HTTPModifierStats{}
	e.statsMu.Unlock()
}

// findScorer returns the first scorer targeting the given ruleID, or nil.
func (e *Engine) findScorer(ruleID string) *Scorer {
	for _, s := range e.scorers {
		if s.canScore(ruleID) {
			return s
		}
	}
	return nil
}

// indexedModifier pairs a modifier with its original YAML declaration index.
type indexedModifier struct {
	mod     Modifier
	yamlIdx int
}
