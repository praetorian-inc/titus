//go:build !wasm

package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeFactories runs the occurrence suite against every Store implementation.
var storeFactories = []struct {
	name string
	open func(t *testing.T) Store
}{

	{"sqlite", func(t *testing.T) Store {
		s, err := NewSQLite(filepath.Join(t.TempDir(), "ds.db"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		return s
	}},
	{"memory", func(t *testing.T) Store { return NewMemory() }},
}

var (
	commitA = &types.CommitMetadata{CommitID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CommitterTimestamp: time.Unix(1_700_000_000, 0).UTC()}
	commitB = &types.CommitMetadata{CommitID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CommitterTimestamp: time.Unix(1_710_000_000, 0).UTC()}
)

func TestStore_Occurrences(t *testing.T) {
	tests := []struct {
		name  string
		provs []types.Provenance   // AddProvenance calls, in order
		occs  [][]types.Occurrence // AddOccurrences calls, in order
		want  []types.Occurrence
	}{
		{
			name: "no rows and no provenance gives an empty result",
			want: []types.Occurrence{},
		},
		{
			name: "rows round-trip with commit date in unix seconds",
			occs: [][]types.Occurrence{{gitOcc("github.com/acme/api", "config.yml", commitA)}},
			want: []types.Occurrence{gitOcc("github.com/acme/api", "config.yml", commitA)},
		},
		{
			name: "AddOccurrences is idempotent",
			occs: [][]types.Occurrence{
				{gitOcc("github.com/acme/api", "config.yml", commitA), gitOcc("github.com/acme/api", "deploy/config.yml", commitB)},
				{gitOcc("github.com/acme/api", "config.yml", commitA), gitOcc("github.com/acme/api", "deploy/config.yml", commitB)},
			},
			want: []types.Occurrence{
				gitOcc("github.com/acme/api", "config.yml", commitA),
				gitOcc("github.com/acme/api", "deploy/config.yml", commitB),
			},
		},
		{
			name: "C-OLDDS-2: legacy acme/api row and new github.com/acme/api row both show",
			provs: []types.Provenance{
				types.GitProvenance{RepoPath: "acme/api", BlobPath: "config.yml", Commit: commitA},
				types.GitProvenance{RepoPath: "github.com/acme/api", BlobPath: "config.yml", Commit: commitA},
			},
			occs: [][]types.Occurrence{{gitOcc("github.com/acme/api", "config.yml", commitA)}},
			want: []types.Occurrence{
				{Kind: "git", Repository: "acme/api", Path: "config.yml", Commit: commitA.CommitID, CommitDate: commitA.CommitterTimestamp, HostRecorded: false},
				gitOcc("github.com/acme/api", "config.yml", commitA),
			},
		},
		{
			name:  "C-FOLDERS-1: identical file in two folders keeps both absolute paths",
			provs: []types.Provenance{types.FileProvenance{FilePath: "config.yml"}, types.FileProvenance{FilePath: "config.yml"}},
			occs: [][]types.Occurrence{
				{{Kind: "file", Path: "config.yml", AbsolutePath: "/x/one/config.yml", HostRecorded: true}},
				{{Kind: "file", Path: "config.yml", AbsolutePath: "/x/two/config.yml", HostRecorded: true}},
			},
			want: []types.Occurrence{
				{Kind: "file", Path: "config.yml", AbsolutePath: "/x/one/config.yml", HostRecorded: true},
				{Kind: "file", Path: "config.yml", AbsolutePath: "/x/two/config.yml", HostRecorded: true},
			},
		},
		{
			name: "C-FOLDERS-2: committed file of two remote-less repos gives two locations",
			provs: []types.Provenance{
				types.GitProvenance{BlobPath: "config.yml", Commit: commitA, RepoRoot: "/x/one"},
				types.GitProvenance{BlobPath: "config.yml", Commit: commitA, RepoRoot: "/x/two"},
			},
			occs: [][]types.Occurrence{
				types.OccurrencesOf(types.GitProvenance{BlobPath: "config.yml", Commit: commitA, RepoRoot: "/x/one"}),
				types.OccurrencesOf(types.GitProvenance{BlobPath: "config.yml", Commit: commitA, RepoRoot: "/x/two"}),
			},
			want: []types.Occurrence{
				{Kind: "git", Path: "config.yml", AbsolutePath: "/x/one/config.yml", Commit: commitA.CommitID, CommitDate: commitA.CommitterTimestamp, HostRecorded: true},
				{Kind: "git", Path: "config.yml", AbsolutePath: "/x/two/config.yml", Commit: commitA.CommitID, CommitDate: commitA.CommitterTimestamp, HostRecorded: true},
			},
		},
		{
			name: "C-CLONEMERGE-1: commitless API occurrence merges into the committed one",
			occs: [][]types.Occurrence{
				{gitOcc("github.com/acme/api", "config.yml", nil)},
				{gitOcc("github.com/acme/api", "config.yml", commitA)},
			},
			want: []types.Occurrence{gitOcc("github.com/acme/api", "config.yml", commitA)},
		},
		{
			name: "C-NONGIT-1: two S3 provenance rows with no location rows give two occurrences",
			provs: []types.Provenance{
				types.ExtendedProvenance{Payload: map[string]any{"path": "s3://b/one.env"}},
				types.ExtendedProvenance{Payload: map[string]any{"path": "s3://b/two.env"}},
			},
			want: []types.Occurrence{
				{Kind: "extended", Path: "s3://b/one.env", HostRecorded: true},
				{Kind: "extended", Path: "s3://b/two.env", HostRecorded: true},
			},
		},
		{
			name: "extended row gets its source from provenance, not from storage",
			provs: []types.Provenance{
				types.ExtendedProvenance{Payload: map[string]any{"source": "confluence", "path": "SPACE/Page"}},
			},
			occs: [][]types.Occurrence{
				types.OccurrencesOf(types.ExtendedProvenance{Payload: map[string]any{"source": "confluence", "path": "SPACE/Page"}}),
				types.OccurrencesOf(types.ExtendedProvenance{Payload: map[string]any{"source": "confluence", "path": "SPACE/Page"}}),
			},
			want: []types.Occurrence{{Kind: "extended", Source: "confluence", Path: "SPACE/Page", HostRecorded: true}},
		},
		{
			name: "extended row without provenance has no source in every store",
			occs: [][]types.Occurrence{{{Kind: "extended", Source: "jira", Path: "PROJ-1", HostRecorded: true}}},
			want: []types.Occurrence{{Kind: "extended", Path: "PROJ-1", HostRecorded: true}},
		},
		{
			name: "SEC-15: hostile path bytes round-trip exactly",
			occs: [][]types.Occurrence{{gitOcc("github.com/acme/api", "x'); DROP TABLE findings;--", commitA), gitOcc("github.com/acme/api", "a\nb", commitA)}},
			want: []types.Occurrence{
				gitOcc("github.com/acme/api", "a\nb", commitA),
				gitOcc("github.com/acme/api", "x'); DROP TABLE findings;--", commitA),
			},
		},
		{
			name: "working-tree occurrence is kept beside its committed twin",
			occs: [][]types.Occurrence{{
				gitOcc("github.com/acme/api", "config.yml", commitA),
				{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", AbsolutePath: "/src/api/config.yml", WorkingTree: true, HostRecorded: true},
			}},
			want: []types.Occurrence{
				gitOcc("github.com/acme/api", "config.yml", commitA),
				{Kind: "git", Repository: "github.com/acme/api", Path: "config.yml", AbsolutePath: "/src/api/config.yml", WorkingTree: true, HostRecorded: true},
			},
		},
	}
	for _, f := range storeFactories {
		for _, tc := range tests {
			t.Run(f.name+"/"+tc.name, func(t *testing.T) {
				s := f.open(t)
				blob := types.ComputeBlobID([]byte("secret"))
				require.NoError(t, s.AddBlob(blob, 6))
				for _, p := range tc.provs {
					require.NoError(t, s.AddProvenance(blob, p))
				}
				for _, o := range tc.occs {
					require.NoError(t, s.AddOccurrences(blob, o))
				}

				got, err := s.GetOccurrences(blob)

				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			})
		}
	}
}

func TestStore_AddOccurrencesInsideExecBatch(t *testing.T) {
	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			blob := types.ComputeBlobID([]byte("secret"))
			occ := gitOcc("github.com/acme/api", "config.yml", commitA)

			err := s.ExecBatch(func(tx Store) error {
				if err := tx.AddBlob(blob, 6); err != nil {
					return err
				}
				return tx.AddOccurrences(blob, []types.Occurrence{occ, occ})
			})

			require.NoError(t, err)
			got, err := s.GetOccurrences(blob)
			require.NoError(t, err)
			assert.Equal(t, []types.Occurrence{occ}, got)
		})
	}
}

func TestStore_OccurrencesAreScopedToTheirBlob(t *testing.T) {
	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			one, two := types.ComputeBlobID([]byte("one")), types.ComputeBlobID([]byte("two"))
			require.NoError(t, s.AddBlob(one, 3))
			require.NoError(t, s.AddBlob(two, 3))
			require.NoError(t, s.AddOccurrences(one, []types.Occurrence{gitOcc("github.com/acme/api", "one.yml", commitA)}))

			got, err := s.GetOccurrences(two)

			require.NoError(t, err)
			assert.Empty(t, got)
		})
	}
}

func TestStore_AddProvenanceStoresWithoutLocations(t *testing.T) {
	for _, f := range storeFactories {
		t.Run(f.name, func(t *testing.T) {
			s := f.open(t)
			blob := types.ComputeBlobID([]byte("secret"))
			require.NoError(t, s.AddBlob(blob, 6))
			prov := types.GitProvenance{
				RepoPath: "github.com/acme/api", BlobPath: "config.yml", Commit: commitA,
				Locations: []types.GitLocation{{Path: "config.yml", Commit: commitA}, {Path: "deploy/config.yml", Commit: commitB}},
			}
			// Equal under the SQLite UNIQUE key, but with different pointers
			// and no Locations: it must not add a second row.
			dup := prov
			dup.Commit = &types.CommitMetadata{CommitID: commitA.CommitID}
			dup.Locations = nil

			require.NoError(t, s.AddProvenance(blob, prov))
			require.NoError(t, s.AddProvenance(blob, dup))
			got, err := s.GetAllProvenance(blob)

			require.NoError(t, err)
			require.Len(t, got, 1)
			g, ok := got[0].(types.GitProvenance)
			require.True(t, ok)
			assert.Empty(t, g.Locations)
			assert.Equal(t, "config.yml", g.BlobPath)
		})
	}
}

func TestMemoryStore_AddProvenanceDedupsOnSQLiteKey(t *testing.T) {
	s := NewMemory()
	blob := types.ComputeBlobID([]byte("secret"))
	provs := []types.Provenance{
		types.FileProvenance{FilePath: "a.yml"},
		types.FileProvenance{FilePath: "a.yml"},
		types.FileProvenance{FilePath: "b.yml"},
		types.GitProvenance{RepoPath: "r", BlobPath: "a.yml", Commit: commitA},
		types.GitProvenance{RepoPath: "r", BlobPath: "a.yml", Commit: &types.CommitMetadata{CommitID: commitA.CommitID}},
		types.GitProvenance{RepoPath: "r", BlobPath: "a.yml", Commit: commitB},
		types.ArchiveProvenance{ArchivePath: "x.zip", MemberPath: "a.yml"},
		types.ArchiveProvenance{ArchivePath: "x.zip", MemberPath: "a.yml"},
		types.ExtendedProvenance{Payload: map[string]any{"path": "s3://b/one.env", "bucket": "b"}},
		types.ExtendedProvenance{Payload: map[string]any{"bucket": "b", "path": "s3://b/one.env"}},
	}
	for _, p := range provs {
		require.NoError(t, s.AddProvenance(blob, p))
	}

	got, err := s.GetAllProvenance(blob)

	require.NoError(t, err)
	assert.Len(t, got, 6)
}
