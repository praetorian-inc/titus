package enum

import (
	"context"

	"github.com/praetorian-inc/titus/pkg/types"
)

// Enumerator discovers content to scan from a source.
type Enumerator interface {
	// Enumerate yields blobs from the source.
	// The callback receives blob content, its ID, and provenance information.
	Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error
}

// Config for enumeration.
type Config struct {
	// Root is the starting path for enumeration.
	Root string

	// IncludeHidden includes hidden files/directories (starting with .).
	IncludeHidden bool

	// MaxFileSize is the maximum file size to process (0 = no limit).
	MaxFileSize int64

	// FollowSymlinks follows symbolic links.
	FollowSymlinks bool

	// ExtractArchives enables text extraction from binary files (comma-separated: xlsx,docx,pdf,zip or 'all').
	ExtractArchives string
}
