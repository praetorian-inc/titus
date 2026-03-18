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
func CompilePatterns(ignoreFile string) (*gitignore.GitIgnore, error) {
	if ignoreFile != "" {
		ig, err := gitignore.CompileIgnoreFile(ignoreFile)
		if err != nil {
			return nil, fmt.Errorf("compiling ignore file %s: %w", ignoreFile, err)
		}
		return ig, nil
	}

	// Parse embedded defaults
	var lines []string
	for _, line := range strings.Split(defaultIgnoreConf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return gitignore.CompileIgnoreLines(lines...), nil
}
