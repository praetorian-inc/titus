package enum

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	gitignore "github.com/sabhiram/go-gitignore"

	"github.com/praetorian-inc/titus/pkg/types"
	"golang.org/x/sync/errgroup"
)

// FilesystemEnumerator enumerates files from a filesystem directory.
type FilesystemEnumerator struct {
	config Config
}

// NewFilesystemEnumerator creates a new filesystem enumerator.
func NewFilesystemEnumerator(config Config) *FilesystemEnumerator {
	return &FilesystemEnumerator{config: config}
}

// fileEntry holds metadata collected during the walk phase.
type fileEntry struct {
	path string
}

// Enumerate walks the filesystem and yields file blobs.
// Phase 1: Walk directory tree and collect eligible file paths (fast, sequential).
// Phase 2: Read files and invoke callback in parallel.
func (e *FilesystemEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Load .gitignore patterns if present
	var ignore *gitignore.GitIgnore
	gitignorePath := filepath.Join(e.config.Root, ".gitignore")
	if _, err := os.Stat(gitignorePath); err == nil {
		ignore, _ = gitignore.CompileIgnoreFile(gitignorePath)
	}

	// Phase 1: Walk and collect eligible file paths
	var files []fileEntry
	err := filepath.Walk(e.config.Root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if info.IsDir() {
			if !e.config.IncludeHidden && isHidden(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		if info.Mode()&os.ModeSymlink != 0 && !e.config.FollowSymlinks {
			return nil
		}

		if !e.config.IncludeHidden && isHidden(info.Name()) {
			return nil
		}

		if e.config.MaxFileSize > 0 && info.Size() > e.config.MaxFileSize {
			return nil
		}

		if ignore != nil {
			relPath, err := filepath.Rel(e.config.Root, path)
			if err != nil {
				return err
			}
			if ignore.MatchesPath(relPath) {
				return nil
			}
		}

		files = append(files, fileEntry{path: path})
		return nil
	})
	if err != nil {
		return err
	}

	// Phase 2: Read and process files in parallel
	numReaders := runtime.NumCPU()
	if numReaders < 1 {
		numReaders = 1
	}

	origCtx := ctx
	g, ctx := errgroup.WithContext(ctx)
	pathsCh := make(chan fileEntry, numReaders*2)

	// Feed paths to readers
	g.Go(func() error {
		defer close(pathsCh)
		for _, f := range files {
			select {
			case pathsCh <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})

	// Parallel readers
	for i := 0; i < numReaders; i++ {
		g.Go(func() error {
			for f := range pathsCh {
				if err := e.processFile(ctx, f.path, callback); err != nil {
					return err
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}
	// If the caller's context was cancelled but all goroutines finished
	// before noticing, propagate the cancellation.
	if origCtx.Err() != nil {
		return origCtx.Err()
	}
	return nil
}

// processFile reads a single file and invokes the callback.
func (e *FilesystemEnumerator) processFile(ctx context.Context, path string, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}

	binary := isBinary(content)

	// Handle binary files with extraction enabled
	if binary && e.config.ExtractArchives != "" {
		ext := getExtension(path)
		if shouldExtract(e.config, ext) {
			extracted, err := ExtractText(path, content, e.config.ExtractLimits)
			if err == nil && len(extracted) > 0 {
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
			return nil
		}
	}

	if binary {
		return nil
	}

	blobID := types.ComputeBlobID(content)
	prov := types.FileProvenance{
		FilePath: path,
	}

	return callback(content, blobID, prov)
}

// shouldExtract checks if a file type should be extracted based on config.
func shouldExtract(config Config, ext string) bool {
	if config.ExtractArchives == "" {
		return false
	}
	if config.ExtractArchives == "all" {
		return true
	}
	types := strings.Split(strings.ToLower(config.ExtractArchives), ",")
	for _, t := range types {
		if strings.TrimSpace(t) == strings.TrimPrefix(ext, ".") {
			return true
		}
	}
	return false
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
	checkSize := len(content)
	if checkSize > 8192 {
		checkSize = 8192
	}
	return bytes.IndexByte(content[:checkSize], 0) != -1
}
