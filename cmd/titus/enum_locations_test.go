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
	"github.com/praetorian-inc/titus/pkg/types"
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

// TestEnumHuman_TruncationMarkerFollowsTruncatedBlobOnly asserts that the
// truncation marker is printed exactly once, as the line right after the
// truncated blob's location list, and never after the untruncated blob.
func TestEnumHuman_TruncationMarkerFollowsTruncatedBlobOnly(t *testing.T) {
	root := t.TempDir()
	truncContent := []byte(locTestSecret)
	cleanContent := []byte("pad\n" + locTestSecret)
	require.NoError(t, os.WriteFile(filepath.Join(root, "trunc.txt"), truncContent, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "clean.txt"), cleanContent, 0o644))

	// The flag lives on a blob's git provenance rows; a filesystem scan never
	// writes one, so seed a truncated row for the first blob only.
	out, err := enumHumanForTest(t, root, func(s store.Store) {
		id := types.ComputeBlobID(truncContent)
		require.NoError(t, s.AddBlob(id, int64(len(truncContent))))
		require.NoError(t, s.AddProvenance(id, types.GitProvenance{
			RepoPath:           "github.com/acme/api",
			BlobPath:           "trunc.txt",
			LocationsTruncated: true,
		}))
	})
	require.NoError(t, err)

	marker := "    " + types.LocationsTruncatedNotice
	assert.Equal(t, 1, strings.Count(out, types.LocationsTruncatedNotice), "marker count:\n%s", out)

	lines := strings.Split(out, "\n")
	at := -1
	for i, l := range lines {
		if l == marker {
			at = i
		}
	}
	require.Greater(t, at, 0, "marker line missing:\n%s", out)

	// Both blobs' lists sit under the same finding in store order, so check
	// neighbours: the marker closes the truncated blob's list (its last line
	// is the scanned file), and the untruncated blob's list is not followed
	// by it.
	assert.True(t, strings.HasSuffix(lines[at-1], "/trunc.txt:1"),
		"marker must directly follow the truncated blob's list:\n%s", out)
	clean := -1
	for i, l := range lines {
		if strings.HasSuffix(l, "/clean.txt:2") {
			clean = i
		}
	}
	require.GreaterOrEqual(t, clean, 0, "untruncated blob still listed:\n%s", out)
	assert.NotEqual(t, marker, lines[clean+1], "marker must not follow the untruncated blob:\n%s", out)
}

// TestEnumHuman_IgnoresScanFormat asserts that enum human output does not
// depend on the scan command's --format global: a leftover "sarif" from scan
// must not make enum fail or change its output.
func TestEnumHuman_IgnoresScanFormat(t *testing.T) {
	orig := scanOutputFormat
	t.Cleanup(func() { scanOutputFormat = orig })
	scanOutputFormat = "sarif"

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.txt"), []byte(locTestSecret), 0o644))

	out, err := enumHumanForTest(t, root, nil)
	require.NoError(t, err)
	assert.Contains(t, out, "1. Rule: "+locTestRuleID)
	assert.Contains(t, out, "a.txt:1")
}
