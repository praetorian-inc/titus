package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var selHelpCommands = []struct {
	name string
	argv []string
}{
	{"report", []string{"report", "--help"}},
	{"report-summary", []string{"report", "summary", "--help"}},
	{"report-sources", []string{"report", "sources", "--help"}},
	{"report-sources-all", []string{"report", "sources", "all", "--help"}},
}

func selHelpText(t *testing.T, argv []string) string {
	t.Helper()
	r := runRootSplit(t, argv...)
	require.NoError(t, r.err)
	return r.stdout
}

// C-HELP-FORMS: each command's help names the three selectors and shows both
// a host-qualified and a host-less repository form.
func TestReportHelp_DocumentsSelectorForms(t *testing.T) {
	for _, tc := range selHelpCommands {
		t.Run(tc.name, func(t *testing.T) {
			help := selHelpText(t, tc.argv)
			for _, flag := range []string{"--namespace", "--repo", "--path"} {
				assert.Contains(t, help, flag)
			}
			assert.Contains(t, help, "github.com/acme/api", "host-qualified form")
			assert.Contains(t, help, "(acme/api)", "host-less form")
		})
	}
}

// C-HELP-LIMIT: each command states that a location recorded without a host
// cannot be tied to one host.
func TestReportHelp_StatesHostLimitation(t *testing.T) {
	for _, tc := range selHelpCommands {
		t.Run(tc.name, func(t *testing.T) {
			help := strings.Join(strings.Fields(selHelpText(t, tc.argv)), " ")
			assert.Contains(t, help, "host not recorded")
			assert.Contains(t, help, "cannot be tied to one host")
			assert.Contains(t, help, "host-qualified --repo or --namespace value may also select")
		})
	}
}
