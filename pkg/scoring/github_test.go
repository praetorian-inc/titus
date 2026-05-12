package scoring

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-github/v57/github"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractGitHubToken_Present(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"token": []byte("github_pat_11AAAAAAA"),
		},
	}
	tok, ok := extractGitHubToken(m)
	assert.True(t, ok)
	assert.Equal(t, "github_pat_11AAAAAAA", tok)
}

func TestExtractGitHubToken_Missing(t *testing.T) {
	m := &types.Match{NamedGroups: map[string][]byte{}}
	_, ok := extractGitHubToken(m)
	assert.False(t, ok)
}

func TestGitHubFineGrainedPermCondition_IsDynamic(t *testing.T) {
	cond := &githubFineGrainedPermCondition{requiredPerm: "write"}
	var mod Modifier
	mod.Condition = cond
	assert.True(t, mod.IsDynamic())
}

func TestGitHubOrgMemberCondition_IsDynamic(t *testing.T) {
	cond := &githubOrgMemberCondition{}
	var mod Modifier
	mod.Condition = cond
	assert.True(t, mod.IsDynamic())
}

func TestGitHubFineGrainedPermCondition_FiresForAdminRepo(t *testing.T) {
	// Simulate GET /user/repos returning one repo with admin=true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `[{"full_name":"owner/repo","permissions":{"admin":true,"push":true,"pull":true}}]`)
	}))
	defer srv.Close()

	cond := &githubFineGrainedPermCondition{
		requiredPerm: "admin",
		clientFactory: func(token string) *github.Client {
			c := github.NewClient(srv.Client())
			base, _ := url.Parse(srv.URL + "/")
			c.BaseURL = base
			c.UploadURL = base
			return c
		},
	}
	m := &types.Match{NamedGroups: map[string][]byte{"token": []byte("github_pat_test")}}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.True(t, fired)
}

func TestGitHubFineGrainedPermCondition_DoesNotFireForReadOnlyRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `[{"full_name":"owner/repo","permissions":{"admin":false,"push":false,"pull":true}}]`)
	}))
	defer srv.Close()

	cond := &githubFineGrainedPermCondition{
		requiredPerm: "write",
		clientFactory: func(token string) *github.Client {
			c := github.NewClient(srv.Client())
			base, _ := url.Parse(srv.URL + "/")
			c.BaseURL = base
			c.UploadURL = base
			return c
		},
	}
	m := &types.Match{NamedGroups: map[string][]byte{"token": []byte("github_pat_test")}}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.False(t, fired)
}

func TestGitHubOrgMemberCondition_FiresWhenOrgsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `[{"login":"praetorian-inc"}]`)
	}))
	defer srv.Close()

	cond := &githubOrgMemberCondition{
		clientFactory: func(token string) *github.Client {
			c := github.NewClient(srv.Client())
			base, _ := url.Parse(srv.URL + "/")
			c.BaseURL = base
			c.UploadURL = base
			return c
		},
	}
	m := &types.Match{NamedGroups: map[string][]byte{"token": []byte("github_pat_test")}}
	fired, err := cond.Evaluate(context.Background(), m)
	require.NoError(t, err)
	assert.True(t, fired)
}
