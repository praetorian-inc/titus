package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileProvenance(t *testing.T) {
	prov := FileProvenance{
		FilePath: "/path/to/file.txt",
	}

	assert.Equal(t, "file", prov.Kind())
	assert.Equal(t, "/path/to/file.txt", prov.Path())
}

func TestGitProvenance_NoCommit(t *testing.T) {
	prov := GitProvenance{
		RepoPath: "/path/to/repo",
		Commit:   nil,
		BlobPath: "src/main.go",
	}

	assert.Equal(t, "git", prov.Kind())
	assert.Equal(t, "src/main.go", prov.Path())
	assert.Nil(t, prov.Commit)
}

func TestGitProvenance_WithCommit(t *testing.T) {
	commitTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	prov := GitProvenance{
		RepoPath: "/path/to/repo",
		Commit: &CommitMetadata{
			CommitID:           "abc123def456",
			AuthorName:         "Jane Doe",
			AuthorEmail:        "jane@example.com",
			AuthorTimestamp:    commitTime,
			CommitterName:      "Jane Doe",
			CommitterEmail:     "jane@example.com",
			CommitterTimestamp: commitTime,
			Message:            "Add new feature",
		},
		BlobPath: "src/feature.go",
	}

	assert.Equal(t, "git", prov.Kind())
	assert.Equal(t, "src/feature.go", prov.Path())
	require.NotNil(t, prov.Commit)
	assert.Equal(t, "abc123def456", prov.Commit.CommitID)
	assert.Equal(t, "Jane Doe", prov.Commit.AuthorName)
	assert.Equal(t, "jane@example.com", prov.Commit.AuthorEmail)
	assert.Equal(t, commitTime, prov.Commit.AuthorTimestamp)
	assert.Equal(t, "Add new feature", prov.Commit.Message)
}

func TestExtendedProvenance(t *testing.T) {
	prov := ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":  "s3",
			"bucket":  "my-bucket",
			"key":     "path/to/object",
			"region":  "us-east-1",
			"version": "v123",
		},
	}

	assert.Equal(t, "extended", prov.Kind())
	assert.Equal(t, "", prov.Path()) // Extended provenance has no standard path

	require.NotNil(t, prov.Payload)
	assert.Len(t, prov.Payload, 5)
	assert.Equal(t, "s3", prov.Payload["source"])
	assert.Equal(t, "my-bucket", prov.Payload["bucket"])
	assert.Equal(t, "us-east-1", prov.Payload["region"])
}

func TestExtendedProvenance_EmptyPayload(t *testing.T) {
	prov := ExtendedProvenance{
		Payload: map[string]interface{}{},
	}

	assert.Equal(t, "extended", prov.Kind())
	require.NotNil(t, prov.Payload)
	assert.Len(t, prov.Payload, 0)
}

func TestExtendedProvenance_NilPayload(t *testing.T) {
	prov := ExtendedProvenance{
		Payload: nil,
	}

	assert.Equal(t, "extended", prov.Kind())
	assert.Nil(t, prov.Payload)
}

func TestProvenance_InterfaceUsage(t *testing.T) {
	// Test that all provenance types implement the Provenance interface
	var provs []Provenance

	fileProv := FileProvenance{FilePath: "/file.txt"}
	gitProv := GitProvenance{RepoPath: "/repo", BlobPath: "main.go"}
	extProv := ExtendedProvenance{Payload: map[string]interface{}{"key": "value"}}

	provs = append(provs, fileProv)
	provs = append(provs, gitProv)
	provs = append(provs, extProv)

	require.Len(t, provs, 3)

	// Test Kind() method
	assert.Equal(t, "file", provs[0].Kind())
	assert.Equal(t, "git", provs[1].Kind())
	assert.Equal(t, "extended", provs[2].Kind())

	// Test Path() method
	assert.Equal(t, "/file.txt", provs[0].Path())
	assert.Equal(t, "main.go", provs[1].Path())
	assert.Equal(t, "", provs[2].Path())
}

func TestCommitMetadata(t *testing.T) {
	authorTime := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	committerTime := time.Date(2024, 1, 15, 11, 0, 0, 0, time.UTC)

	commit := CommitMetadata{
		CommitID:           "abc123",
		AuthorName:         "Alice",
		AuthorEmail:        "alice@example.com",
		AuthorTimestamp:    authorTime,
		CommitterName:      "Bob",
		CommitterEmail:     "bob@example.com",
		CommitterTimestamp: committerTime,
		Message:            "Fix bug",
	}

	assert.Equal(t, "abc123", commit.CommitID)
	assert.Equal(t, "Alice", commit.AuthorName)
	assert.Equal(t, "alice@example.com", commit.AuthorEmail)
	assert.Equal(t, authorTime, commit.AuthorTimestamp)
	assert.Equal(t, "Bob", commit.CommitterName)
	assert.Equal(t, "bob@example.com", commit.CommitterEmail)
	assert.Equal(t, committerTime, commit.CommitterTimestamp)
	assert.Equal(t, "Fix bug", commit.Message)
}
