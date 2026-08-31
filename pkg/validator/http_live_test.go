package validator

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLive_GitHubPullHeaders(t *testing.T) {
	token := liveGitHubToken(t)
	data, err := validatorsFS.ReadFile("validators/github.yaml")
	require.NoError(t, err)
	var cfg ValidatorsConfig
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.NotEmpty(t, cfg.Validators)

	result, err := NewHTTPValidator(cfg.Validators[0], nil).Validate(context.Background(), &types.Match{
		RuleID:      "np.github.2",
		NamedGroups: map[string][]byte{"token": []byte(token)},
	})
	require.NoError(t, err)
	require.Equal(t, types.StatusValid, result.Status, "message=%s", result.Message)
	require.NotEmpty(t, result.Details["X-OAuth-Scopes"], "GitHub 200 should pull X-OAuth-Scopes")
	assert.Contains(t, result.Message, "X-OAuth-Scopes:")
	t.Logf("status=%s pulled=%q", result.Status, result.Details["X-OAuth-Scopes"])
}

func TestLive_GitLabPullJSON(t *testing.T) {
	token := strings.TrimSpace(os.Getenv("GITLAB_TOKEN"))
	if token == "" {
		t.Skip("GITLAB_TOKEN not set")
	}
	data, err := validatorsFS.ReadFile("validators/gitlab.yaml")
	require.NoError(t, err)
	var cfg ValidatorsConfig
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.NotEmpty(t, cfg.Validators)

	result, err := NewHTTPValidator(cfg.Validators[0], nil).Validate(context.Background(), &types.Match{
		RuleID: "np.gitlab.2",
		Groups: [][]byte{[]byte(token)},
	})
	require.NoError(t, err)
	require.Equal(t, types.StatusValid, result.Status, "message=%s", result.Message)
	require.NotEmpty(t, result.Details["scopes"], "GitLab 200 should pull json scopes")
	assert.Contains(t, result.Message, "scopes:")
	t.Logf("status=%s pulled=%q", result.Status, result.Details["scopes"])
}

func liveGitHubToken(t *testing.T) string {
	t.Helper()
	if tok := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); tok != "" {
		return tok
	}
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		t.Skip("no GITHUB_TOKEN and gh auth token failed")
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" {
		t.Skip("gh auth token was empty")
	}
	return tok
}
