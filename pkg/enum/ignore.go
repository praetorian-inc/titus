package enum

import (
	gitignore "github.com/sabhiram/go-gitignore"

	"github.com/praetorian-inc/titus/pkg/enum/ignore"
)

// CompileIgnorePatterns compiles gitignore-style patterns from the given ignore
// file path. If ignoreFile is empty, the embedded default ignore.conf is used.
// Returns an error if a user-supplied file cannot be read.
//
// Deprecated: Use ignore.CompilePatterns instead.
func CompileIgnorePatterns(ignoreFile string) (*gitignore.GitIgnore, error) {
	return ignore.CompilePatterns(ignoreFile)
}
