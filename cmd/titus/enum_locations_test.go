package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/enum"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enumHumanForTest runs runEnumScan in human format over a temp directory with
// only the synthetic location rule enabled and returns stdout. seed, when not
// nil, writes rows into the enum datastore before the scan opens it. Every
// enum global it sets is restored when the test ends.
func enumHumanForTest(t *testing.T, root string, seed func(s store.Store)) (string, error) {
	t.Helper()
	rulesFile := filepath.Join(t.TempDir(), "rules.yml")
	writeRulesYAML(t, rulesFile, []ruleStub{{ID: locTestRuleID, BaseScore: 50}})

	origFormat, origOutput := enumFormat, enumOutput
	origRules, origInclude, origExclude := enumRulesPath, enumRulesInclude, enumRulesExclude
	origRuleset, origNoisy := enumRuleset, enumIncludeNoisy
	t.Cleanup(func() {
		enumFormat, enumOutput = origFormat, origOutput
		enumRulesPath, enumRulesInclude, enumRulesExclude = origRules, origInclude, origExclude
		enumRuleset, enumIncludeNoisy = origRuleset, origNoisy
	})
	enumFormat = "human"
	// A file store, as enum uses by default: MemoryStore.AddMatch does not
	// dedup by StructuralID, so :memory: repeats a re-yielded blob's match.
	enumOutput = filepath.Join(t.TempDir(), "enum.db")
	enumRulesPath = rulesFile
	enumRulesInclude = `^test\.locations\.`
	enumRulesExclude = ""
	enumRuleset = "default"
	enumIncludeNoisy = false

	if seed != nil {
		s, err := store.New(store.Config{Path: enumOutput})
		require.NoError(t, err)
		seed(s)
		require.NoError(t, s.Close())
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	err := runEnumScan(cmd, enum.NewFilesystemEnumerator(enum.Config{Root: root}), "filesystem")
	return out.String(), err
}

// TestEnumHuman_PrintsEveryLocation asserts that enum human output prints,
// under the finding line, one location line per file holding the secret.
func TestEnumHuman_PrintsEveryLocation(t *testing.T) {
	root := t.TempDir()
	content := []byte("first line\n" + locTestSecret)
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.txt"), content, 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "b.txt"), content, 0o644))

	out, err := enumHumanForTest(t, root, nil)
	require.NoError(t, err)

	ruleLine := "1. Rule: " + locTestRuleID
	idx := strings.Index(out, ruleLine)
	require.GreaterOrEqual(t, idx, 0, "finding line missing:\n%s", out)
	body := out[idx+len(ruleLine):]
	assert.Equal(t, 1, strings.Count(body, "a.txt:2"), "a.txt location:\n%s", out)
	assert.Equal(t, 1, strings.Count(body, "b.txt:2"), "b.txt location:\n%s", out)
	assert.NotContains(t, out, "locations truncated", "filesystem blobs are never truncated")
}
