package enum

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gitignore "github.com/sabhiram/go-gitignore"

	"github.com/praetorian-inc/titus/pkg/types"
)

// FilesystemEnumerator enumerates files from a filesystem directory.
type FilesystemEnumerator struct {
	config Config
}

// NewFilesystemEnumerator creates a new filesystem enumerator.
func NewFilesystemEnumerator(config Config) *FilesystemEnumerator {
	return &FilesystemEnumerator{config: config}
}

// Enumerate walks the filesystem and yields file blobs.
func (e *FilesystemEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Load .gitignore patterns if present
	var ignore *gitignore.GitIgnore
	gitignorePath := filepath.Join(e.config.Root, ".gitignore")
	if _, err := os.Stat(gitignorePath); err == nil {
		ignore, _ = gitignore.CompileIgnoreFile(gitignorePath)
	}

	return filepath.Walk(e.config.Root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip directories
		if info.IsDir() {
			// Skip hidden directories if not included
			if !e.config.IncludeHidden && isHidden(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks unless configured to follow
		if info.Mode()&os.ModeSymlink != 0 && !e.config.FollowSymlinks {
			return nil
		}

		// Skip hidden files if not included
		if !e.config.IncludeHidden && isHidden(info.Name()) {
			return nil
		}

		// Apply size limit
		if e.config.MaxFileSize > 0 && info.Size() > e.config.MaxFileSize {
			return nil
		}

		// Check gitignore patterns
		if ignore != nil {
			relPath, err := filepath.Rel(e.config.Root, path)
			if err != nil {
				return err
			}
			if ignore.MatchesPath(relPath) {
				return nil
			}
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}

		// Check if binary
		binary := isBinary(content)

		// Handle binary files with extraction enabled
		if binary && e.config.ExtractArchives {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".xlsx" || ext == ".docx" || ext == ".pdf" {
				// Try to extract text from binary file
				extracted, err := ExtractText(path, content)
				if err == nil && len(extracted) > 0 {
					// Yield each extracted piece of content
					for _, ec := range extracted {
						blobID := types.ComputeBlobID(ec.Content)
						prov := types.ArchiveProvenance{
							ArchivePath: path,
							MemberPath:  ec.Name,
						}
						if err := callback(ec.Content, blobID, prov); err != nil {
							return err
						}
					}
				}
				// Skip the binary file itself (extracted or not)
				return nil
			}
		}

		// Skip binary files (not extracted or extraction disabled)
		if binary {
			return nil
		}

		// Compute blob ID
		blobID := types.ComputeBlobID(content)

		// Create file provenance
		prov := types.FileProvenance{
			FilePath: path,
		}

		// Yield to callback
		return callback(content, blobID, prov)
	})
}

// isHidden checks if a filename is hidden (starts with .).
// The special entries "." and ".." are NOT considered hidden.
func isHidden(name string) bool {
	if name == "." || name == ".." {
		return false
	}
	return strings.HasPrefix(name, ".")
}

// isBinary detects if content is binary by checking first 8KB for null bytes.
func isBinary(content []byte) bool {
	// Check first 8KB
	checkSize := len(content)
	if checkSize > 8192 {
		checkSize = 8192
	}

	// Look for null bytes
	return bytes.IndexByte(content[:checkSize], 0) != -1
}
