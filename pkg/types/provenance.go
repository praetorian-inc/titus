package types

import "time"

// Provenance tracks where a blob was discovered.
type Provenance interface {
	Kind() string
	// Path returns displayable path (if applicable)
	Path() string
}

// FileProvenance for filesystem files.
type FileProvenance struct {
	FilePath string
}

// Kind returns "file".
func (f FileProvenance) Kind() string {
	return "file"
}

// Path returns the file path.
func (f FileProvenance) Path() string {
	return f.FilePath
}

// GitProvenance for git repository blobs.
type GitProvenance struct {
	RepoPath string
	Commit   *CommitMetadata // nil if not tracking commit info
	BlobPath string          // path within repo at commit
}

// Kind returns "git".
func (g GitProvenance) Kind() string {
	return "git"
}

// Path returns the blob path within the repository.
func (g GitProvenance) Path() string {
	return g.BlobPath
}

// CommitMetadata holds git commit information.
type CommitMetadata struct {
	CommitID           string
	AuthorName         string
	AuthorEmail        string
	AuthorTimestamp    time.Time
	CommitterName      string
	CommitterEmail     string
	CommitterTimestamp time.Time
	Message            string
}

// ExtendedProvenance for custom sources (S3, HTTP, etc.).
type ExtendedProvenance struct {
	Payload map[string]interface{}
}

// Kind returns "extended".
func (e ExtendedProvenance) Kind() string {
	return "extended"
}

// Path returns empty string as extended provenance has no standard path.
func (e ExtendedProvenance) Path() string {
	return ""
}
