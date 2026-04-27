package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScan_EndToEnd_FindingHasScore(t *testing.T) {
	// This is an integration smoke test: we manually drive the pieces of runScan
	// that are relevant to scoring — we don't invoke cobra / enumerator / matcher.
	// Goal: confirm that when AddFinding is called with a score from the engine,
	// GetFindings returns the score back.

	tmpDir := t.TempDir()
	s, err := store.New(store.Config{Path: filepath.Join(tmpDir, "test.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	// Load a real rule so we have a real BaseScore path.
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	require.NoError(t, err)
	if len(rules) == 0 {
		t.Skip("no builtin rules available")
	}

	r := rules[0]
	require.NoError(t, s.AddRule(r))

	engine, err := buildScoringEngine()
	require.NoError(t, err)

	f := &types.Finding{
		ID:     "test-finding-abc",
		RuleID: r.ID,
		Groups: [][]byte{[]byte("synthetic")},
	}
	// Pass a match with no named groups — no modifier fires, returns base-only.
	match := &types.Match{RuleID: r.ID, NamedGroups: map[string][]byte{}}
	f.Score = engine.Score(context.Background(), f, []*types.Match{match}, r)
	require.NoError(t, s.AddFinding(f))

	findings, err := s.GetFindings()
	require.NoError(t, err)
	require.Len(t, findings, 1)

	got := findings[0]
	require.NotNil(t, got.Score, "expected Score to be non-nil after round-trip")
	assert.Equal(t, r.BaseScore, got.Score.Base)
	assert.Equal(t, types.SeverityForScore(r.BaseScore), got.Score.SuggestedSeverity)
}
