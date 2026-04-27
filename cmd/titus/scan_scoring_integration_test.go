package main

import (
	"encoding/json"
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
	origAccessibility := scanAccessibility
	scanOutputPath = dsPath
	scanRuleset = "all" // np.aws.1 is in np.assets, not default
	scanAccessibility = "public" // disable accessibility penalty so this test isolates engine scoring
	t.Cleanup(func() {
		scanOutputPath = origOutputPath
		scanRuleset = origRuleset
		scanAccessibility = origAccessibility
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

// TestRunScan_UnscoredRule_StillEmitsFindingWithBaseOnly scans a fixture
// containing a Slack Bot Token (np.slack.2), which has no scorer in aws.yaml
// or github.yaml. It verifies that the scoring injection at scan.go:293 does
// not silently drop findings for unscored rules, and that the resulting Score
// carries the rule's BaseScore with an empty (non-nil) Applied slice.
//
// The empty-non-nil invariant matters for JSON consumers: Applied marshaling
// as null vs [] is a schema-breaking difference.
func TestRunScan_UnscoredRule_StillEmitsFindingWithBaseOnly(t *testing.T) {
	// np.slack.2 pattern: xoxb-[0-9]{10,12}-[0-9]{10,14}-[a-zA-Z0-9]{23,25}
	// BaseScore is 70. No scorer targets np.slack.2, so Final == Base == 70.
	slackToken := "xoxb-893582989554-899326518131-JRHeVv1o9Cf99fwDpuortR2D"
	tmpDir := t.TempDir()
	fixturePath := filepath.Join(tmpDir, "fixture.txt")
	require.NoError(t, os.WriteFile(fixturePath, []byte("SLACK_API_TOKEN="+slackToken+"\n"), 0644))

	dsPath := filepath.Join(tmpDir, "scan.ds")

	origOutputPath := scanOutputPath
	origRuleset := scanRuleset
	origAccessibility := scanAccessibility
	scanOutputPath = dsPath
	scanRuleset = "all" // include np.slack.* rules
	scanAccessibility = "public" // disable accessibility penalty so this test isolates engine scoring
	t.Cleanup(func() {
		scanOutputPath = origOutputPath
		scanRuleset = origRuleset
		scanAccessibility = origAccessibility
	})

	require.NoError(t, runScan(scanCmd, []string{fixturePath}))

	s, err := store.New(store.Config{Path: filepath.Join(dsPath, "datastore.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	findings, err := s.GetFindings()
	require.NoError(t, err)

	var slackFinding *types.Finding
	for _, f := range findings {
		if f.RuleID == "np.slack.2" {
			slackFinding = f
			break
		}
	}
	require.NotNil(t, slackFinding, "expected np.slack.2 finding to be emitted (not dropped)")

	// Score must be non-nil — the engine always populates it.
	require.NotNil(t, slackFinding.Score, "Score must not be nil even for unscored rules")

	// Base and Final must equal the rule's BaseScore (70).
	const wantBase = 70
	assert.Equal(t, wantBase, slackFinding.Score.Base, "Base should equal rule BaseScore")
	assert.Equal(t, wantBase, slackFinding.Score.Final, "Final should equal Base when no modifiers fired")

	// SuggestedSeverity must be consistent with Final.
	assert.Equal(t, types.SeverityForScore(wantBase), slackFinding.Score.SuggestedSeverity)

	// Applied must be a non-nil empty slice — NOT nil. Marshaling nil as JSON
	// produces "null" while []ScoreModifier{} produces "[]", which is a schema
	// difference that breaks downstream consumers.
	require.NotNil(t, slackFinding.Score.Applied, "Applied must be non-nil (empty slice) for JSON schema stability")
	assert.Len(t, slackFinding.Score.Applied, 0, "Applied must be empty when no modifiers fired")

	// Explicitly verify the JSON marshal shape: Applied must render as [].
	raw, err := json.Marshal(slackFinding.Score)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"Applied":[]`, "Applied must marshal as [] not null")
}

// TestRunScan_MultiMatchDedup_ScoredOncePerFinding verifies the architectural
// invariant that Engine.Score is called exactly once per unique finding even
// when a rule matches multiple times in the same file.
//
// Strategy: scan a fixture containing two occurrences of the same AKIA key.
// Both matches yield the same finding ID (same rule + same capture groups) so
// they deduplicate into a single finding. Assertions:
//
//  1. Exactly one finding is emitted (dedup working).
//  2. Score.Applied has exactly one entry of "akia-long-term", not two.
//     If scoring were called once per match, Applied would contain duplicate
//     entries; the presence of exactly one proves scoring fired once.
func TestRunScan_MultiMatchDedup_ScoredOncePerFinding(t *testing.T) {
	// Two occurrences of the same AKIA key in the same file.
	const akiaKey = "AKIADEADBEEFDEADBEEF"
	fixtureContent := "AWS_KEY=" + akiaKey + "\n" +
		"BACKUP_KEY=" + akiaKey + "\n"

	tmpDir := t.TempDir()
	fixturePath := filepath.Join(tmpDir, "fixture.txt")
	require.NoError(t, os.WriteFile(fixturePath, []byte(fixtureContent), 0644))

	dsPath := filepath.Join(tmpDir, "scan.ds")

	origOutputPath := scanOutputPath
	origRuleset := scanRuleset
	origAccessibility := scanAccessibility
	scanOutputPath = dsPath
	scanRuleset = "all"
	scanAccessibility = "public" // disable accessibility penalty so this test isolates engine scoring
	t.Cleanup(func() {
		scanOutputPath = origOutputPath
		scanRuleset = origRuleset
		scanAccessibility = origAccessibility
	})

	require.NoError(t, runScan(scanCmd, []string{fixturePath}))

	s, err := store.New(store.Config{Path: filepath.Join(dsPath, "datastore.db")})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	findings, err := s.GetFindings()
	require.NoError(t, err)

	// Collect all np.aws.1 findings (should be exactly 1 after dedup).
	var awsFindings []*types.Finding
	for _, f := range findings {
		if f.RuleID == "np.aws.1" {
			awsFindings = append(awsFindings, f)
		}
	}
	require.Len(t, awsFindings, 1, "two identical AKIA matches must deduplicate into exactly one finding")

	f := awsFindings[0]
	require.NotNil(t, f.Score, "finding must have a Score")

	// If scoring ran once per match instead of once per finding, Applied would
	// contain the "akia-long-term" modifier twice. Exactly one entry proves
	// the engine was called once for this finding.
	require.Len(t, f.Score.Applied, 1,
		"Applied must contain exactly 1 entry; multiple entries would indicate "+
			"scoring ran more than once for the same finding")
	assert.Equal(t, "akia-long-term", f.Score.Applied[0].Name,
		"the single applied modifier must be akia-long-term")
}
