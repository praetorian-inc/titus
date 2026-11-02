package explore

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// pagerArgs calls openSource and returns the argument list of the process its
// command would start, or nil when it returns no command (the snippet
// overlay). tea.ExecProcess keeps its *exec.Cmd in unexported fields, so the
// arguments are read by reflection.
func pagerArgs(t *testing.T, m *Model) []string {
	t.Helper()
	cmd := m.openSource()
	if cmd == nil {
		return nil
	}
	var find func(v reflect.Value, depth int) []string
	find = func(v reflect.Value, depth int) []string {
		if depth > 6 {
			return nil
		}
		switch v.Kind() {
		case reflect.Interface, reflect.Pointer:
			if v.IsNil() {
				return nil
			}
			return find(v.Elem(), depth+1)
		case reflect.Struct:
			if a := v.FieldByName("Args"); a.IsValid() && a.Kind() == reflect.Slice && a.Type().Elem().Kind() == reflect.String {
				out := make([]string, a.Len())
				for i := range out {
					out[i] = a.Index(i).String()
				}
				return out
			}
			for i := range v.NumField() {
				if out := find(v.Field(i), depth+1); out != nil {
					return out
				}
			}
		}
		return nil
	}
	args := find(reflect.ValueOf(cmd()), 0)
	if args == nil {
		t.Fatalf("openSource returned a command that starts no process")
	}
	return args
}

// openSourceModel builds a model whose selected match carries prov.
func openSourceModel(prov types.GitProvenance) *Model {
	match := matchWith(3, types.OccurrencesOf(prov)...)
	match.Provenance = []types.Provenance{prov}
	f := &findingRow{FindingID: "f-open", RuleName: "Open Rule", Matches: []*matchRow{match}}
	m := newTestModel([]*findingRow{f})
	return &m
}

// X3 (ENG-9178): under --git a working-tree-only file arrives as
// GitProvenance with a WorkingTree location, not FileProvenance. Opening the
// source must page the on-disk file at RepoRoot/Path, as it does for a plain
// folder scan, instead of falling back to the snippet overlay.
func TestOpenSource_GitWorkingTreeLocationOpensFileOnDisk(t *testing.T) {
	t.Setenv("PAGER", "less")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "new.txt"), []byte("k = v\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := openSourceModel(types.GitProvenance{
		RepoPath:  "github.com/acme/api",
		RepoRoot:  root,
		BlobPath:  "new.txt",
		Locations: []types.GitLocation{{Path: "new.txt", WorkingTree: true}},
	})

	args := pagerArgs(t, m)
	if args == nil {
		t.Fatalf("openSource fell back to the snippet overlay for a working-tree location whose file exists on disk")
	}
	want := filepath.Join(root, "new.txt")
	if got := args[len(args)-1]; got != want {
		t.Errorf("pager opens %q, want the working-tree file %q (args %q)", got, want, args)
	}
	if m.activeOverlay == overlaySource {
		t.Errorf("snippet overlay opened alongside the pager")
	}
}

// A working-tree location is chosen over committed ones in the same
// provenance; the committed path's on-disk file is not what was scanned.
func TestOpenSource_GitPrefersWorkingTreeOverCommittedLocation(t *testing.T) {
	t.Setenv("PAGER", "less")
	root := t.TempDir()
	for _, p := range []string{"old.txt", "copy.txt"} {
		if err := os.WriteFile(filepath.Join(root, p), []byte("k = v\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	commit := &types.CommitMetadata{CommitID: "0123456789abcdef0123456789abcdef01234567"}
	m := openSourceModel(types.GitProvenance{
		RepoPath: "github.com/acme/api",
		RepoRoot: root,
		BlobPath: "old.txt",
		Commit:   commit,
		Locations: []types.GitLocation{
			{Path: "old.txt", Commit: commit},
			{Path: "copy.txt", WorkingTree: true},
		},
	})

	args := pagerArgs(t, m)
	if args == nil {
		t.Fatalf("openSource fell back to the snippet overlay for a provenance with a working-tree location")
	}
	if got, want := args[len(args)-1], filepath.Join(root, "copy.txt"); got != want {
		t.Errorf("pager opens %q, want the working-tree file %q", got, want)
	}
}

// A committed-only location is never opened from disk, even when a file of
// that name exists there: its content may differ from the committed blob.
func TestOpenSource_GitCommittedOnlyLocationShowsSnippet(t *testing.T) {
	t.Setenv("PAGER", "less")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "old.txt"), []byte("unrelated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commit := &types.CommitMetadata{CommitID: "0123456789abcdef0123456789abcdef01234567"}
	m := openSourceModel(types.GitProvenance{
		RepoPath:  "github.com/acme/api",
		RepoRoot:  root,
		BlobPath:  "old.txt",
		Commit:    commit,
		Locations: []types.GitLocation{{Path: "old.txt", Commit: commit}},
	})

	if args := pagerArgs(t, m); args != nil {
		t.Errorf("committed-only location opened on disk with args %q, want the snippet overlay", args)
	}
	if m.activeOverlay != overlaySource {
		t.Errorf("activeOverlay = %v, want the snippet overlay", m.activeOverlay)
	}
}

// Control for pagerArgs: a plain-folder FileProvenance pages its file.
func TestOpenSource_FileProvenanceOpensFile(t *testing.T) {
	t.Setenv("PAGER", "less")
	path := filepath.Join(t.TempDir(), "creds.txt")
	if err := os.WriteFile(path, []byte("k = v\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prov := types.FileProvenance{FilePath: path}
	match := matchWith(3, types.OccurrencesOf(prov)...)
	match.Provenance = []types.Provenance{prov}
	m := newTestModel([]*findingRow{{FindingID: "f-file", RuleName: "Open Rule", Matches: []*matchRow{match}}})

	args := pagerArgs(t, &m)
	if args == nil {
		t.Fatalf("openSource fell back to the snippet overlay for an existing FileProvenance path")
	}
	if got := args[len(args)-1]; got != path {
		t.Errorf("pager opens %q, want %q", got, path)
	}
}
