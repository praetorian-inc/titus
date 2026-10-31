package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoveralls_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/repos/github/octocat/hello-world", r.URL.Path)
		assert.Equal(t, "token abcdefghijklmnopqrstuvwxyzab12345cd", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"service":"github","name":"hello-world","id":12345}`))
	}))
	defer server.Close()

	v := NewCoverallsValidatorWithClient(server.Client(), server.URL)
	match := &types.Match{
		RuleID:      "kingfisher.coveralls.2",
		NamedGroups: map[string][]byte{"token": []byte("abcdefghijklmnopqrstuvwxyzab12345cd")},
		Snippet: types.Snippet{
			Before: []byte("# see https://coveralls.io/github/octocat/hello-world\n"),
		},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestCoveralls_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewCoverallsValidatorWithClient(server.Client(), server.URL)
	match := &types.Match{
		RuleID:      "kingfisher.coveralls.2",
		NamedGroups: map[string][]byte{"token": []byte("invalidtokenxxxxxxxxxxxxxxxxxxxxxxxx")},
		Snippet: types.Snippet{
			After: []byte("\ncoveralls.io/gitlab/group/project badge"),
		},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestCoveralls_NoRepoPath(t *testing.T) {
	v := NewCoverallsValidator()
	match := &types.Match{
		RuleID:      "kingfisher.coveralls.2",
		NamedGroups: map[string][]byte{"token": []byte("abcdefghijklmnopqrstuvwxyzab12345cd")},
		Snippet:     types.Snippet{Before: []byte("some unrelated context")},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "repo path not found")
}

func TestCoveralls_NoToken(t *testing.T) {
	v := NewCoverallsValidator()
	match := &types.Match{
		RuleID:      "kingfisher.coveralls.2",
		NamedGroups: map[string][]byte{},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no token found")
}

func TestCoveralls_APIPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/repos/github/octocat/hello-world", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewCoverallsValidatorWithClient(server.Client(), server.URL)
	match := &types.Match{
		RuleID:      "kingfisher.coveralls.2",
		NamedGroups: map[string][]byte{"token": []byte("abcdefghijklmnopqrstuvwxyzab12345cd")},
		Snippet: types.Snippet{
			Before: []byte("curl coveralls.io/api/v1/repos/github/octocat/hello-world"),
		},
	}
	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
}

func TestCoveralls_CanValidate(t *testing.T) {
	v := NewCoverallsValidator()
	assert.True(t, v.CanValidate("kingfisher.coveralls.2"))
	assert.False(t, v.CanValidate("kingfisher.coveralls.1"))
	assert.False(t, v.CanValidate("kingfisher.other.1"))
}

func TestExtractCoverallsRepo(t *testing.T) {
	tests := []struct {
		name    string
		snippet types.Snippet
		want    string
	}{
		{
			name:    "github URL",
			snippet: types.Snippet{Before: []byte("https://coveralls.io/github/octocat/hello-world")},
			want:    "github/octocat/hello-world",
		},
		{
			name:    "gitlab URL",
			snippet: types.Snippet{After: []byte("coveralls.io/gitlab/group/project")},
			want:    "gitlab/group/project",
		},
		{
			name:    "bitbucket URL",
			snippet: types.Snippet{Matching: []byte("coveralls.io/bitbucket/user/repo")},
			want:    "bitbucket/user/repo",
		},
		{
			name:    "API path",
			snippet: types.Snippet{Before: []byte("coveralls.io/api/v1/repos/github/org/repo")},
			want:    "github/org/repo",
		},
		{
			name:    "badge URL with /repos/ prefix",
			snippet: types.Snippet{Before: []byte("https://coveralls.io/repos/github/org/repo/badge.svg")},
			want:    "github/org/repo",
		},
		{
			name:    "case insensitive",
			snippet: types.Snippet{Before: []byte("Coveralls.IO/GitHub/octocat/hello-world")},
			want:    "GitHub/octocat/hello-world",
		},
		{
			name:    "no match",
			snippet: types.Snippet{Before: []byte("no coveralls info here")},
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractCoverallsRepo(tt.snippet))
		})
	}
}
