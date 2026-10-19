package validator

import (
	"context"
	"os"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator/internal/vcrtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_jira_Valid(t *testing.T) {
	runJiraCassetteCase(t, "testdata/jira/valid", types.StatusValid)
}

func Test_jira_Invalid(t *testing.T) {
	runJiraCassetteCase(t, "testdata/jira/invalid", types.StatusInvalid)
}

func runJiraCassetteCase(t *testing.T, cassette string, want types.ValidationStatus) {
	t.Helper()

	isRecording := os.Getenv("RECORD") == "1"
	cassetteFile := cassette + ".yaml"
	if !isRecording {
		if _, err := os.Stat(cassetteFile); os.IsNotExist(err) {
			t.Skipf(
				"cassette not recorded yet; run:\n"+
					"  SECRET_PLAINTEXT=<valid-token> JIRA_EMAIL=<email> JIRA_DOMAIN=<org>.atlassian.net "+
					"RECORD=1 go test ./pkg/validator/ -run Test_jira_Valid\n"+
					"  SECRET_PLAINTEXT=<invalid-token> JIRA_EMAIL=<email> JIRA_DOMAIN=<org>.atlassian.net "+
					"RECORD=1 go test ./pkg/validator/ -run Test_jira_Invalid",
			)
		}
	}

	var (
		tokenVal []byte
		email    string
		domain   string
	)

	if isRecording {
		pt := os.Getenv("SECRET_PLAINTEXT")
		if pt == "" {
			t.Fatal("RECORD=1 requires SECRET_PLAINTEXT=<real-token>")
		}
		email = os.Getenv("JIRA_EMAIL")
		if email == "" {
			t.Fatal("RECORD=1 requires JIRA_EMAIL=<real-email>")
		}
		domain = os.Getenv("JIRA_DOMAIN")
		if domain == "" {
			t.Fatal("RECORD=1 requires JIRA_DOMAIN=<org>.atlassian.net")
		}
		tokenVal = []byte(pt)
	} else {
		tokenVal = []byte(vcrtest.Placeholder)
		email = "user@example.com"
		domain = "example.atlassian.net"
	}

	match := &types.Match{
		RuleID:      "kingfisher.jira.2",
		NamedGroups: map[string][]byte{"token": tokenVal},
		Snippet: types.Snippet{
			Before:   []byte("JIRA_USER=\"" + email + "\"\n"),
			Matching: []byte("JIRA_PASSWORD=\"" + string(tokenVal) + "\""),
			After:    []byte("\nJIRA_HOST=https://" + domain + "\n"),
		},
	}

	var opts []vcrtest.Option
	if isRecording && domain != "example.atlassian.net" {
		opts = append(opts, vcrtest.WithExtraRedactions([2]string{domain, "example.atlassian.net"}))
	}
	client := vcrtest.Client(t, cassette, opts...)
	v := NewAtlassianValidatorWithClient(client)

	result, err := v.Validate(context.Background(), match)
	require.NoError(t, err, "Validate must not return a non-nil error")
	assert.Equal(t, want, result.Status,
		"jira cassette %s: unexpected validation status", cassette)
}
