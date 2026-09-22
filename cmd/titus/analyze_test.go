package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAnalyzeCmd(args ...string) (*cobra.Command, *bytes.Buffer) {
	buf := new(bytes.Buffer)
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	return cmd, buf
}

func TestMatchesTypeHint(t *testing.T) {
	tests := []struct {
		ruleID   string
		ruleName string
		hint     string
		want     bool
	}{
		{"np.aws.6", "AWS API Key", "aws", true},
		{"np.aws.6", "AWS API Key", "AWS", true},
		{"np.github.1", "GitHub Token", "github", true},
		{"np.github.1", "GitHub Token", "gitlab", false},
		{"np.gitlab.2", "GitLab PAT", "gitlab", true},
		{"np.slack.2", "Slack Token", "slack", true},
		{"np.slack.2", "Slack Token", "aws", false},
	}
	for _, tt := range tests {
		t.Run(tt.ruleID+"_"+tt.hint, func(t *testing.T) {
			r := &types.Rule{ID: tt.ruleID, Name: tt.ruleName}
			got := matchesTypeHint(r, tt.hint)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContainsIgnoreCaseAnalyze(t *testing.T) {
	assert.True(t, containsIgnoreCaseAnalyze("np.aws.6", "aws"))
	assert.True(t, containsIgnoreCaseAnalyze("np.AWS.6", "aws"))
	assert.True(t, containsIgnoreCaseAnalyze("np.aws.6", "AWS"))
	assert.False(t, containsIgnoreCaseAnalyze("np.aws.6", "github"))
	assert.False(t, containsIgnoreCaseAnalyze("ab", "abc"))
}

func TestReadAnalyzeInput_Token(t *testing.T) {
	analyzeToken = "test-token-value"
	analyzeFile = ""
	defer func() { analyzeToken = "" }()

	cmd, _ := newAnalyzeCmd()
	data, err := readAnalyzeInput(cmd)
	require.NoError(t, err)
	assert.Equal(t, "test-token-value", string(data))
}

func TestReadAnalyzeInput_NoInput(t *testing.T) {
	analyzeToken = ""
	analyzeFile = ""

	cmd, _ := newAnalyzeCmd()
	data, err := readAnalyzeInput(cmd)
	require.NoError(t, err)
	assert.Nil(t, data)
}

func TestOutputAnalyzeJSON(t *testing.T) {
	analyzeFormat = "json"
	defer func() { analyzeFormat = "human" }()

	results := []analyzedFinding{
		{
			finding: &types.Finding{
				ID:     "test-finding-1",
				RuleID: "np.test.1",
				Groups: [][]byte{[]byte("secret-value")},
				Score:  &types.Score{Final: 75, Base: 50, SuggestedSeverity: "high"},
				Owner:  &types.OwnerInfo{User: "alice", Email: "alice@example.com"},
				Resources: []types.ResourceInfo{
					{Service: "aws", Type: "s3_bucket", Name: "prod-data"},
				},
			},
			validation: &types.ValidationResult{Status: "valid", Confidence: 1.0, Message: "key is active"},
		},
	}

	ruleMap := map[string]*types.Rule{
		"np.test.1": {ID: "np.test.1", Name: "Test Rule"},
	}

	cmd, buf := newAnalyzeCmd()
	err := outputAnalyzeJSON(cmd, results, ruleMap)
	require.NoError(t, err)

	var out analyzeOutput
	err = json.Unmarshal(buf.Bytes(), &out)
	require.NoError(t, err)
	require.Len(t, out.Findings, 1)

	f := out.Findings[0]
	assert.Equal(t, "test-finding-1", f.ID)
	assert.Equal(t, "np.test.1", f.RuleID)
	assert.Equal(t, "Test Rule", f.RuleName)
	assert.Equal(t, 75, f.Score.Final)
	assert.Equal(t, "alice", f.Owner.User)
	assert.Len(t, f.Resources, 1)
	assert.Equal(t, "s3_bucket", f.Resources[0].Type)
	require.NotNil(t, f.Validation)
	assert.Equal(t, types.StatusValid, f.Validation.Status)
	assert.Equal(t, "key is active", f.Validation.Message)
}

func TestOutputAnalyzeHuman(t *testing.T) {
	reportColor = "never"
	defer func() { reportColor = "auto" }()

	results := []analyzedFinding{
		{
			finding: &types.Finding{
				ID:     "test-finding-1",
				RuleID: "np.test.1",
				Groups: [][]byte{[]byte("secret-value")},
				Score:  &types.Score{Final: 85, Base: 50, SuggestedSeverity: "critical"},
				Owner:  &types.OwnerInfo{User: "alice", Email: "alice@example.com", AccountID: "123456"},
				Resources: []types.ResourceInfo{
					{Service: "aws", Type: "s3_bucket", Name: "prod-data"},
					{Service: "aws", Type: "secret", Name: "db-password", Region: "us-east-1"},
				},
			},
			validation: &types.ValidationResult{Status: "valid", Confidence: 1.0, Message: "key is active"},
		},
	}

	ruleMap := map[string]*types.Rule{
		"np.test.1": {ID: "np.test.1", Name: "Test Rule"},
	}

	cmd, buf := newAnalyzeCmd()
	err := outputAnalyzeHuman(cmd, results, ruleMap)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Credential Analysis")
	assert.Contains(t, output, "1 finding(s)")
	assert.Contains(t, output, "Test Rule")
	assert.Contains(t, output, "Validation:")
	assert.Contains(t, output, "valid")
	assert.Contains(t, output, "key is active")
	assert.Contains(t, output, "85/100")
	assert.Contains(t, output, "critical")
	assert.Contains(t, output, "alice")
	assert.Contains(t, output, "alice@example.com")
	assert.Contains(t, output, "123456")
	assert.Contains(t, output, "s3_bucket")
	assert.Contains(t, output, "prod-data")
	assert.Contains(t, output, "us-east-1")
	assert.Contains(t, output, "secret-value")
}

func TestOutputAnalyzeHuman_NoScore(t *testing.T) {
	reportColor = "never"
	defer func() { reportColor = "auto" }()

	results := []analyzedFinding{
		{
			finding: &types.Finding{
				ID:     "test-finding-1",
				RuleID: "np.test.1",
				Groups: [][]byte{[]byte("value")},
			},
		},
	}

	ruleMap := map[string]*types.Rule{
		"np.test.1": {ID: "np.test.1", Name: "Minimal Rule"},
	}

	cmd, buf := newAnalyzeCmd()
	err := outputAnalyzeHuman(cmd, results, ruleMap)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Minimal Rule")
	assert.NotContains(t, output, "Score:")
	assert.NotContains(t, output, "Owner:")
	assert.NotContains(t, output, "Resources:")
	assert.NotContains(t, output, "Validation:")
}

func TestOutputAnalyzeHuman_ScoringTrail(t *testing.T) {
	reportColor = "never"
	defer func() { reportColor = "auto" }()

	results := []analyzedFinding{
		{
			finding: &types.Finding{
				ID:     "test-finding-1",
				RuleID: "np.test.1",
				Groups: [][]byte{[]byte("value")},
				Score: &types.Score{
					Final:             65,
					Base:              50,
					SuggestedSeverity: "high",
					Applied: []types.ScoreModifier{
						{Name: "is-admin", Scorer: "aws", Kind: "delta", Value: 15, Priority: 50},
					},
				},
			},
		},
	}

	ruleMap := map[string]*types.Rule{
		"np.test.1": {ID: "np.test.1", Name: "Test Rule"},
	}

	cmd, buf := newAnalyzeCmd()
	err := outputAnalyzeHuman(cmd, results, ruleMap)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Scoring trail:")
	assert.Contains(t, output, "is-admin")
	assert.Contains(t, output, "delta=15")
}

func TestLoadAnalyzeRules(t *testing.T) {
	analyzeType = ""
	rules, ruleMap, err := loadAnalyzeRules()
	require.NoError(t, err)
	assert.Greater(t, len(rules), 0)
	assert.Equal(t, len(rules), len(ruleMap))
}

func TestLoadAnalyzeRules_TypeFilter(t *testing.T) {
	analyzeType = "aws"
	defer func() { analyzeType = "" }()

	rules, _, err := loadAnalyzeRules()
	require.NoError(t, err)
	assert.Greater(t, len(rules), 0)
	for _, r := range rules {
		assert.True(t, strings.Contains(strings.ToLower(r.ID), "aws") || strings.Contains(strings.ToLower(r.Name), "aws"),
			"rule %s should match aws hint", r.ID)
	}
}

func TestLoadAnalyzeRules_UnknownType(t *testing.T) {
	analyzeType = "nonexistent_service_xyz"
	defer func() { analyzeType = "" }()

	_, _, err := loadAnalyzeRules()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no rules match")
}
