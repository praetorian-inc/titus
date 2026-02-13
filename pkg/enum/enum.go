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

// ExtractionLimits defines safety limits for archive extraction.
type ExtractionLimits struct {
	MaxSize  int64 // Max uncompressed size per file (10MB default)
	MaxTotal int64 // Max total bytes extracted from one archive (100MB default)
	MaxDepth int   // Max nested archive depth (5 default)
}

// DefaultExtractionLimits returns the default extraction safety limits.
func DefaultExtractionLimits() ExtractionLimits {
	return ExtractionLimits{
		MaxSize:  10 * 1024 * 1024,
		MaxTotal: 100 * 1024 * 1024,
		MaxDepth: 5,
	}
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

	// ExtractArchives enables text extraction from binary files (extensions: xlsx,docx,pdf,zip or 'all').
	ExtractArchives string

	// ExtractLimits specifies safety limits for archive extraction.
	ExtractLimits ExtractionLimits
}
