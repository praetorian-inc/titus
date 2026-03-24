package ignore

import (
	_ "embed"
	"fmt"
	"strings"

	gitignore "github.com/sabhiram/go-gitignore"
)

//go:embed ignore.conf
var defaultIgnoreConf string

// CompilePatterns compiles gitignore-style patterns from the given ignore
// file path. If ignoreFile is empty, the embedded default ignore.conf is used.
// Returns an error if a user-supplied file cannot be read.
//
// extraLines are optional additional gitignore-style patterns
func CompilePatterns(ignoreFile string, extraLines ...string) (*gitignore.GitIgnore, error) {
	if ignoreFile != "" {
		ig, err := gitignore.CompileIgnoreFileAndLines(ignoreFile, extraLines...)
		if err != nil {
			return nil, fmt.Errorf("compiling ignore file %s: %w", ignoreFile, err)
		}
		return ig, nil
	}

	lines := append(strings.Split(defaultIgnoreConf, "\n"), extraLines...)
	return gitignore.CompileIgnoreLines(lines...), nil
}
