package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/titus/pkg/scoring"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunScan_EngineBuilt_AppliedPopulated verifies that when runScan builds
// an engine from the embedded scorers, a finding on np.aws.1 with an AKIA
// key-id named group receives the akia-long-term modifier.
func TestRunScan_EngineBuilt_AppliedPopulated(t *testing.T) {
	engine, err := buildScoringEngine()
	require.NoError(t, err)
	require.NotNil(t, engine)

	rule := &types.Rule{ID: "np.aws.1", BaseScore: 48}
	finding := &types.Finding{ID: "f1", RuleID: rule.ID}
	match := &types.Match{
		RuleID:      "np.aws.1",
		NamedGroups: map[string][]byte{"key_id": []byte("AKIADEADBEEFDEADBEEF")},
	}

	score := engine.Score(finding, []*types.Match{match}, rule)

	assert.Equal(t, 58, score.Final) // 48 + 10
	require.Len(t, score.Applied, 1)
	assert.Equal(t, "akia-long-term", score.Applied[0].Name)
	assert.Equal(t, "aws-key-scope", score.Applied[0].Scorer)
	assert.Equal(t, "delta", score.Applied[0].Kind)
	assert.Equal(t, 10, score.Applied[0].Value)
}

// TestRunScan_ASIAPrefix_DecrementsScore verifies that an ASIA key drops the
// score by 10 (temporary STS session token, lower risk).
func TestRunScan_ASIAPrefix_DecrementsScore(t *testing.T) {
	engine, err := buildScoringEngine()
	require.NoError(t, err)

	rule := &types.Rule{ID: "np.aws.1", BaseScore: 48}
	match := &types.Match{NamedGroups: map[string][]byte{"key_id": []byte("ASIAXXXXXXXXXXXXXXXX")}}
	score := engine.Score(&types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)
	assert.Equal(t, 38, score.Final)
}

// TestRunScan_AIDAPrefix_ClampsToInfo verifies that an AIDA identifier drops
// to set_score 10 regardless of base (IAM user identifier, not a credential).
func TestRunScan_AIDAPrefix_ClampsToInfo(t *testing.T) {
	engine, err := buildScoringEngine()
	require.NoError(t, err)

	rule := &types.Rule{ID: "np.aws.1", BaseScore: 48}
	match := &types.Match{NamedGroups: map[string][]byte{"key_id": []byte("AIDAXXXXXXXXXXXXXXXX")}}
	score := engine.Score(&types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)
	assert.Equal(t, 10, score.Final)
	assert.Equal(t, "info", score.SuggestedSeverity)
}

// TestRunScan_GitHubFineGrainedPAT verifies the github.yaml scorer applies
// the fine-grained-pat-prefix modifier to np.github.7 findings.
func TestRunScan_GitHubFineGrainedPAT(t *testing.T) {
	engine, err := buildScoringEngine()
	require.NoError(t, err)

	rule := &types.Rule{ID: "np.github.7", BaseScore: 65}
	match := &types.Match{
		NamedGroups: map[string][]byte{
			"token": []byte("github_pat_11ABCDEFG0000000000000000000000000000000000000000000000000000000000000000000000"),
		},
	}
	score := engine.Score(&types.Finding{RuleID: rule.ID}, []*types.Match{match}, rule)
	assert.Equal(t, 55, score.Final) // 65 - 10

	// Confirm the engine is a *scoring.Engine for interface sanity.
	_ = engine.(*scoring.Engine)
}

// TestRunScan_E2E_AKIAFinding_PopulatesApplied runs the scan pipeline against
// an in-memory fixture and asserts the resulting finding has the AKIA modifier
// recorded in Score.Applied.
//
// This is a higher-fidelity test than the buildScoringEngine unit tests above;
// it verifies the wiring at the finding-creation hook in scan.go works
// end-to-end.
//
// Implementation notes:
//   - np.aws.1 is in the "np.assets" ruleset, not "default". We temporarily set
//     scanRuleset = "all" so the rule is included.
//   - scanOutputPath is set to a temp directory path; runScan calls
//     datastore.Open which creates a subdirectory with "datastore.db" inside it.
//     We reopen the store at that nested path after the scan completes.
//   - AKIADEADBEEFDEADBEEF is the rule's own positive example and does NOT
//     contain "EXAMPLE" (the ignore_if_contains filter).
func TestRunScan_E2E_AKIAFinding_PopulatesApplied(t *testing.T) {
	tmpDir := t.TempDir()
	// Use AKIADEADBEEFDEADBEEF — the rule's own example, no "EXAMPLE" substring.
	fixturePath := filepath.Join(tmpDir, "fixture.txt")
	require.NoError(t, os.WriteFile(fixturePath, []byte("AWS_ACCESS_KEY_ID=AKIADEADBEEFDEADBEEF\n"), 0644))

	dsPath := filepath.Join(tmpDir, "scan.ds")

	// Temporarily override package-level scan flags.
	origOutputPath := scanOutputPath
	origRuleset := scanRuleset
	scanOutputPath = dsPath
	scanRuleset = "all" // np.aws.1 is in np.assets, not default
	t.Cleanup(func() {
		scanOutputPath = origOutputPath
		scanRuleset = origRuleset
	})

	require.NoError(t, runScan(scanCmd, []string{fixturePath}))

	// datastore.Open creates dsPath/ directory with datastore.db inside.
	s, err := store.New(store.Config{Path: filepath.Join(dsPath, "datastore.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	findings, err := s.GetFindings()
	require.NoError(t, err)

	var awsFinding *types.Finding
	for _, f := range findings {
		if f.RuleID == "np.aws.1" {
			awsFinding = f
			break
		}
	}
	require.NotNil(t, awsFinding, "expected np.aws.1 finding, got: %v", findings)
	require.NotNil(t, awsFinding.Score, "finding has no Score")

	assert.Equal(t, 58, awsFinding.Score.Final, "Final = base(48) + akia delta(+10)")
	require.Len(t, awsFinding.Score.Applied, 1)
	assert.Equal(t, "akia-long-term", awsFinding.Score.Applied[0].Name)
	assert.Equal(t, "aws-key-scope", awsFinding.Score.Applied[0].Scorer)
	assert.Equal(t, "delta", awsFinding.Score.Applied[0].Kind)
	assert.Equal(t, 10, awsFinding.Score.Applied[0].Value)
}
