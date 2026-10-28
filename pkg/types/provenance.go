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

	// RepoRoot is the absolute scan root: the directory working-tree
	// location paths are relative to.
	RepoRoot string `json:",omitempty"`
	// RepoTop is the absolute top level of the repository, which committed
	// location paths are relative to, when the scan root is below it. Empty
	// means RepoRoot is the top level.
	RepoTop string `json:",omitempty"`
	// Host is the host the repository identity resolved to, as the resolver
	// returned it. "" is a recorded value (no host was resolved), not an
	// absent one.
	Host string `json:",omitempty"`
	// RemoteIdentity is true when RepoPath is a normalized remote identity
	// (host/owner/repo) rather than a local folder.
	RemoteIdentity bool `json:",omitempty"`
	// Locations lists every location of the blob in this repository. When
	// empty, the primary location (BlobPath, Commit) is the only one.
	Locations []GitLocation `json:",omitempty"`
	// LocationsTruncated is true when some locations of this blob were not
	// recorded because the history index reached its size limit; the count
	// of missing locations is unknown, so Locations is a lower bound.
	LocationsTruncated bool `json:",omitempty"`
}

// GitLocation is one location of a blob within a repository: its path at its
// earliest-seen commit, or its path in the working tree.
type GitLocation struct {
	Path        string
	Commit      *CommitMetadata // nil for working-tree locations
	WorkingTree bool
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

// Path returns the "path" value from the payload if present.
func (e ExtendedProvenance) Path() string {
	if p, ok := e.Payload["path"].(string); ok {
		return p
	}
	return ""
}
