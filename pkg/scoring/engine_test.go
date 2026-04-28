package scoring

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Confirms the basic Scorer/Modifier types exist with the expected shape.
// This test also acts as a compile-time guard for engine_test.go imports.
func TestScorer_BasicShape(t *testing.T) {
	m := Modifier{
		Name:      "test",
		Priority:  50,
		Kind:      ModifierKindDelta,
		Value:     10,
		Condition: &matchLengthCondition{Op: matchLengthOpGT, Value: 0},
	}
	s := &Scorer{Name: "test-scorer", RuleIDs: []string{"np.test.1"}, Modifiers: []Modifier{m}}
	assert.Equal(t, "test-scorer", s.Name)
	assert.True(t, s.canScore("np.test.1"))
	assert.False(t, s.canScore("np.other.1"))

	// Match is unused here but the types must line up.
	_ = &types.Match{}
}

func TestEngine_NoScorerRegistered_ReturnsBaseOnly(t *testing.T) {
	engine := NewEngine(nil, EngineConfig{})
	rule := &types.Rule{ID: "np.test.1", BaseScore: 50}
	finding := &types.Finding{ID: "f1", RuleID: rule.ID}
	match := &types.Match{RuleID: rule.ID}

	score := engine.Score(context.Background(), finding, []*types.Match{match}, rule)

	assert.Equal(t, 50, score.Final)
	assert.Equal(t, 50, score.Base)
	assert.Equal(t, "medium", score.SuggestedSeverity)
	assert.Empty(t, score.Applied)
}

func TestEngine_NoMatchingScorer_ReturnsBaseOnly(t *testing.T) {
	scorer := &Scorer{
		Name:    "other-scorer",
		RuleIDs: []string{"np.other.1"},
		Modifiers: []Modifier{{
			Name: "unused", Kind: ModifierKindDelta, Value: 100,
			Condition: &matchLengthCondition{Op: matchLengthOpGT, Value: 0},
		}},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{})
	rule := &types.Rule{ID: "np.test.1", BaseScore: 30}
	finding := &types.Finding{ID: "f1", RuleID: rule.ID}

	score := engine.Score(context.Background(), finding, []*types.Match{{}}, rule)

	assert.Equal(t, 30, score.Final)
	assert.Empty(t, score.Applied)
}

// Helper: builds a deterministic "always fires" condition for math tests.
func alwaysFires() Condition {
	return &matchLengthCondition{Op: matchLengthOpGT, Value: -1} // any length > -1 → true
}

func TestEngine_DeltaStacks(t *testing.T) {
	scorer := &Scorer{
		Name:    "stack",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			{Name: "a", Kind: ModifierKindDelta, Value: 5, Condition: alwaysFires()},
			{Name: "b", Kind: ModifierKindDelta, Value: 10, Condition: alwaysFires()},
			{Name: "c", Kind: ModifierKindDelta, Value: -3, Condition: alwaysFires()},
		},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{})
	rule := &types.Rule{ID: "np.test.1", BaseScore: 50}
	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{{Snippet: types.Snippet{Matching: []byte("x")}}}, rule)
	assert.Equal(t, 62, score.Final) // 50 + 5 + 10 - 3
	assert.Len(t, score.Applied, 3)
}

func TestEngine_SetScoreReplaces(t *testing.T) {
	scorer := &Scorer{
		Name:    "replace",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			{Name: "boost", Kind: ModifierKindDelta, Value: 20, Condition: alwaysFires()},
			{Name: "force-to-10", Kind: ModifierKindSetScore, Value: 10, Condition: alwaysFires()},
		},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{})
	rule := &types.Rule{ID: "np.test.1", BaseScore: 50}
	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{{Snippet: types.Snippet{Matching: []byte("x")}}}, rule)
	// Declaration order, no priorities: +20 then set_score=10 → final 10.
	assert.Equal(t, 10, score.Final)
	assert.Len(t, score.Applied, 2)
}

func TestEngine_DeltaAfterSetScore(t *testing.T) {
	scorer := &Scorer{
		Name:    "replace-then-add",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			{Name: "force-to-10", Kind: ModifierKindSetScore, Value: 10, Condition: alwaysFires()},
			{Name: "bonus", Kind: ModifierKindDelta, Value: 5, Condition: alwaysFires()},
		},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{})
	rule := &types.Rule{ID: "np.test.1", BaseScore: 80}
	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{{Snippet: types.Snippet{Matching: []byte("x")}}}, rule)
	assert.Equal(t, 15, score.Final) // set to 10, then +5
}

func TestEngine_ClampsLow(t *testing.T) {
	scorer := &Scorer{
		Name:    "dive",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			{Name: "a", Kind: ModifierKindDelta, Value: -200, Condition: alwaysFires()},
		},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{})
	rule := &types.Rule{ID: "np.test.1", BaseScore: 50}
	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{{Snippet: types.Snippet{Matching: []byte("x")}}}, rule)
	assert.Equal(t, 0, score.Final)
	assert.Equal(t, "info", score.SuggestedSeverity)
}

func TestEngine_ClampsHigh(t *testing.T) {
	scorer := &Scorer{
		Name:    "soar",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			{Name: "a", Kind: ModifierKindDelta, Value: 200, Condition: alwaysFires()},
		},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{})
	rule := &types.Rule{ID: "np.test.1", BaseScore: 50}
	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{{Snippet: types.Snippet{Matching: []byte("x")}}}, rule)
	assert.Equal(t, 100, score.Final)
	assert.Equal(t, "critical", score.SuggestedSeverity)
}

// erroringCondition always returns an error — used to prove modifier is skipped.
type erroringCondition struct{}

func (e *erroringCondition) Evaluate(_ context.Context, m *types.Match) (bool, error) {
	return false, fmt.Errorf("synthetic error")
}

func TestEngine_PriorityDESCOrdering(t *testing.T) {
	scorer := &Scorer{
		Name:    "priority-test",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			// Declared order: low, high, mid. Expected eval: high, mid, low.
			{Name: "low", Priority: 10, Kind: ModifierKindDelta, Value: 1, Condition: alwaysFires()},
			{Name: "high", Priority: 100, Kind: ModifierKindSetScore, Value: 50, Condition: alwaysFires()},
			{Name: "mid", Priority: 50, Kind: ModifierKindDelta, Value: 10, Condition: alwaysFires()},
		},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{})
	rule := &types.Rule{ID: "np.test.1", BaseScore: 5}
	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{{Snippet: types.Snippet{Matching: []byte("x")}}}, rule)
	// Eval order by priority DESC: high (set=50) → mid (+10) → low (+1) → 61.
	assert.Equal(t, 61, score.Final)
	require.Len(t, score.Applied, 3)
	assert.Equal(t, "high", score.Applied[0].Name)
	assert.Equal(t, "mid", score.Applied[1].Name)
	assert.Equal(t, "low", score.Applied[2].Name)
}

func TestEngine_TieBreak_YAMLOrderASC(t *testing.T) {
	scorer := &Scorer{
		Name:    "tiebreak",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			// Same priority — YAML declaration order wins (first = A).
			{Name: "A", Priority: 50, Kind: ModifierKindDelta, Value: 1, Condition: alwaysFires()},
			{Name: "B", Priority: 50, Kind: ModifierKindDelta, Value: 2, Condition: alwaysFires()},
			{Name: "C", Priority: 50, Kind: ModifierKindDelta, Value: 3, Condition: alwaysFires()},
		},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{})
	rule := &types.Rule{ID: "np.test.1", BaseScore: 0}
	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{{Snippet: types.Snippet{Matching: []byte("x")}}}, rule)
	assert.Equal(t, 6, score.Final)
	require.Len(t, score.Applied, 3)
	assert.Equal(t, "A", score.Applied[0].Name)
	assert.Equal(t, "B", score.Applied[1].Name)
	assert.Equal(t, "C", score.Applied[2].Name)
}

// TestEngine_ConcurrentScore_NoRace verifies that calling Score() concurrently
// from many goroutines does not produce a data race on shared *httpCondition
// state. This test must be run with -race; it should FAIL before the fix
// (per-finding cache mutation) and PASS after (engine-level cache via
// evaluateWithCache).
func TestEngine_ConcurrentScore_NoRace(t *testing.T) {
	// Start a mock HTTP server that always returns 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	// Build a scorer with a SHARED *httpCondition (as the engine does in Score).
	sharedCond := &httpCondition{
		method:    "GET",
		url:       srv.URL,
		auth:      scorerAuth{},
		firesWhen: &statusCodeLeaf{Code: 200},
	}
	scorer := &Scorer{
		Name:    "race-scorer",
		RuleIDs: []string{"np.race.1"},
		Modifiers: []Modifier{
			{Name: "active", Kind: ModifierKindDelta, Value: 10,
				Condition: sharedCond},
		},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{ScopeEnabled: true, Timeout: 5 * defaultModifierTimeout})
	rule := &types.Rule{ID: "np.race.1", BaseScore: 50}

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			finding := &types.Finding{RuleID: rule.ID}
			match := &types.Match{NamedGroups: map[string][]byte{}}
			engine.Score(context.Background(), finding, []*types.Match{match}, rule)
		}()
	}
	wg.Wait()
}

// TestEngine_RateLimitedStats verifies that a 429 response from a dynamic
// modifier increments engine.Stats().RateLimited. This test should FAIL before
// the fix (classifyHTTPError not called) and PASS after.
func TestEngine_RateLimitedStats(t *testing.T) {
	// Mock server that always returns 429 (even on retry).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	cond := &httpCondition{
		method:    "GET",
		url:       srv.URL,
		auth:      scorerAuth{},
		firesWhen: &statusCodeLeaf{Code: 200},
	}
	scorer := &Scorer{
		Name:    "rate-limit-scorer",
		RuleIDs: []string{"np.rl.1"},
		Modifiers: []Modifier{
			{Name: "check", Kind: ModifierKindDelta, Value: 10, Condition: cond},
		},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{ScopeEnabled: true, Timeout: 5 * defaultModifierTimeout})
	rule := &types.Rule{ID: "np.rl.1", BaseScore: 50}
	finding := &types.Finding{RuleID: rule.ID}
	match := &types.Match{NamedGroups: map[string][]byte{}}

	engine.Score(context.Background(), finding, []*types.Match{match}, rule)

	stats := engine.Stats()
	assert.Equal(t, 1, stats.RateLimited, "RateLimited counter must be incremented after a 429 response")
}

func TestEngine_ConditionError_SkipsModifier_ContinuesScoring(t *testing.T) {
	var warnings []string
	scorer := &Scorer{
		Name:    "mixed",
		RuleIDs: []string{"np.test.1"},
		Modifiers: []Modifier{
			{Name: "broken", Kind: ModifierKindDelta, Value: 100, Condition: &erroringCondition{}},
			{Name: "works", Kind: ModifierKindDelta, Value: 5, Condition: alwaysFires()},
		},
	}
	engine := NewEngine([]*Scorer{scorer}, EngineConfig{})
	engine.warnf = func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}
	rule := &types.Rule{ID: "np.test.1", BaseScore: 50}
	score := engine.Score(context.Background(), &types.Finding{RuleID: rule.ID}, []*types.Match{{Snippet: types.Snippet{Matching: []byte("x")}}}, rule)
	assert.Equal(t, 55, score.Final) // 50 + 5 (broken skipped)
	require.Len(t, score.Applied, 1)
	assert.Equal(t, "works", score.Applied[0].Name)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "broken")
	assert.Contains(t, warnings[0], "synthetic error")
}
