package validator

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJenkinsValidator_Name(t *testing.T) {
	v := NewJenkinsValidator()
	assert.Equal(t, "jenkins", v.Name())
}

func TestJenkinsValidator_CanValidate(t *testing.T) {
	v := NewJenkinsValidator()

	tests := []struct {
		name   string
		ruleID string
		want   bool
	}{
		{"jenkins token rule", "np.jenkins.1", true},
		{"jenkins admin password rule", "np.jenkins.2", true},
		{"other rule", "np.aws.1", false},
		{"empty rule", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, v.CanValidate(tt.ruleID))
		})
	}
}

func TestIsCrumbMatch(t *testing.T) {
	tests := []struct {
		name string
		ctx  string
		want bool
	}{
		{
			name: "Jenkins-Crumb header",
			ctx:  "curl -X POST 'http://jenkins.example.com/job/build' -H 'Jenkins-Crumb:440561953171ba44ace9740562d172bb'",
			want: true,
		},
		{
			name: "crumb_issuer reference",
			ctx:  "crumb_issuer = '/crumbIssuer/api/xml'\ncrumb = '440561953171ba44ace9740562d172bb'",
			want: true,
		},
		{
			name: "API token context",
			ctx:  "JENKINS_USER=admin\nJENKINS_TOKEN=11f4274ec59be12eace9a08b08ee13d54b",
			want: false,
		},
		{
			name: "admin password context",
			ctx:  "Please use the following password to proceed to installation:\n\nbd9627decc6346d780b3b6ab6ea8fe1f",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isCrumbMatch(tt.ctx))
		})
	}
}

func TestExtractJenkinsURL(t *testing.T) {
	tests := []struct {
		name    string
		ctx     string
		wantURL string
	}{
		{
			name:    "JENKINS_URL assignment",
			ctx:     "export JENKINS_URL=https://jenkins.example.com\nexport JENKINS_TOKEN=abc123",
			wantURL: "https://jenkins.example.com",
		},
		{
			name:    "jenkins_url with single quotes",
			ctx:     "jenkins_url = 'http://10.1.188.121:8080'\njenkins_passwd = 'abc'",
			wantURL: "http://10.1.188.121:8080",
		},
		{
			name:    "JENKINS variable (no _URL suffix)",
			ctx:     "export JENKINS=jenkins-cicd.apps.sno.openshiftlabs.net\nexport JENKINS_TOKEN=abc",
			wantURL: "",
		},
		{
			name:    "fallback URL with jenkins in hostname",
			ctx:     "curl -X POST 'http://jenkins.lsfusion.luxsoft.by/job/build' --user user:pass",
			wantURL: "http://jenkins.lsfusion.luxsoft.by/job/build",
		},
		{
			name:    "no URL in context",
			ctx:     "JENKINS_TOKEN=11811f784531053132519844d047186074",
			wantURL: "",
		},
		{
			name:    "JENKINS_HOST assignment",
			ctx:     "JENKINS_HOST=https://ci.example.com\nJENKINS_TOKEN=abc",
			wantURL: "https://ci.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJenkinsURL(tt.ctx)
			assert.Equal(t, tt.wantURL, got)
		})
	}
}

func TestExtractJenkinsUser(t *testing.T) {
	tests := []struct {
		name     string
		ctx      string
		wantUser string
	}{
		{
			name:     "JENKINS_USER export",
			ctx:      "export JENKINS_USER=justin-admin\nexport JENKINS_TOKEN=abc",
			wantUser: "justin-admin",
		},
		{
			name:     "jenkins_user assignment with quotes",
			ctx:      "jenkins_user = 'root'\njenkins_passwd = 'abc'",
			wantUser: "root",
		},
		{
			name:     "JENKINS_USERNAME",
			ctx:      "JENKINS_USERNAME=deploy-bot\nJENKINS_TOKEN=abc",
			wantUser: "deploy-bot",
		},
		{
			name:     "no user in context",
			ctx:      "JENKINS_TOKEN=abc\nJENKINS_URL=https://jenkins.example.com",
			wantUser: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJenkinsUser(tt.ctx)
			assert.Equal(t, tt.wantUser, got)
		})
	}
}

func TestExtractHostFromURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"https with port", "https://jenkins.example.com:8443", "jenkins.example.com"},
		{"http without port", "http://10.1.188.121", "10.1.188.121"},
		{"https with path", "https://ci.example.com/jenkins", "ci.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractHostFromURL(tt.url))
		})
	}
}

func TestJenkinsValidator_CrumbDetection(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{[]byte("440561953171ba44ace9740562d172bb")},
		Snippet: types.Snippet{
			Before:   []byte("curl -X POST 'http://jenkins.example.com/job/build' --user admin:pass -H '"),
			Matching: []byte("Jenkins-Crumb:440561953171ba44ace9740562d172bb"),
			After:    []byte("'"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "crumb")
}

func TestJenkinsValidator_TokenAdjacentToCrumb(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{[]byte("11f4274ec59be12eace9a08b08ee13d54b")},
		Snippet: types.Snippet{
			Before:   []byte("JENKINS_CRUMB=440561953171ba44ace9740562d172bb\nJENKINS_URL=https://nonexistent.invalid\nJENKINS_USER=admin\n"),
			Matching: []byte("jenkins_token=11f4274ec59be12eace9a08b08ee13d54b"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.NotContains(t, result.Message, "crumb", "token match should not be classified as crumb just because JENKINS_CRUMB is in surrounding context")
}

func TestJenkinsValidator_MissingToken(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no token")
}

func TestJenkinsValidator_MissingURL(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{[]byte("11811f784531053132519844d047186074")},
		Snippet: types.Snippet{
			Before:   []byte("some random context\n"),
			Matching: []byte("11811f784531053132519844d047186074"),
			After:    []byte("\nmore context"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no Jenkins URL")
}

func TestJenkinsValidator_MissingUser(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{[]byte("11811f784531053132519844d047186074")},
		Snippet: types.Snippet{
			Before:   []byte("JENKINS_URL=https://jenkins.example.com\n"),
			Matching: []byte("11811f784531053132519844d047186074"),
			After:    []byte("\nmore context"),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "no Jenkins username")
}

func TestJenkinsValidator_SkipsLocalhost(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{[]byte("11811f784531053132519844d047186074")},
		Snippet: types.Snippet{
			Before:   []byte("JENKINS_URL=http://localhost:8080\nJENKINS_USER=admin\n"),
			Matching: []byte("11811f784531053132519844d047186074"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "localhost")
}

func TestJenkinsValidator_ConnectionError(t *testing.T) {
	v := NewJenkinsValidator()

	match := &types.Match{
		RuleID: "np.jenkins.1",
		Groups: [][]byte{[]byte("11811f784531053132519844d047186074")},
		Snippet: types.Snippet{
			Before:   []byte("JENKINS_URL=https://nonexistent.invalid\nJENKINS_USER=admin\n"),
			Matching: []byte("11811f784531053132519844d047186074"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "connection failed")
}
