package enum

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
)

// hardenedGitConfig overrides repository configuration that could change the
// shape of git's output or run programs the repository chooses (SEC-13).
var hardenedGitConfig = []string{
	"-c", "log.showSignature=false",
	"-c", "core.fsmonitor=false",
	"-c", "core.quotePath=true",
	"-c", "log.showRoot=true",
	"-c", "i18n.logOutputEncoding=UTF-8",
	"-c", "diff.external=",
	// diff.relative=true would make the history index's raw diff paths
	// relative to the working directory and drop changes outside it;
	// blobIndexLogArgs also overrides it on the command line.
	"-c", "diff.relative=false",
	"-c", "core.hooksPath=/dev/null",
	// A partial clone fetches missing objects on demand through the
	// repository's remote, whose uploadpack/sshCommand it controls (V1).
	// Lazy fetch is off (GIT_NO_LAZY_FETCH, GIT_ALLOW_PROTOCOL below);
	// these also stop git spawning detached maintenance or gc children.
	"-c", "protocol.allow=never",
	"-c", "maintenance.auto=false",
	"-c", "gc.auto=0",
}

// hardenedGitEnv is appended after the filtered inherited environment; exec
// keeps the last duplicate, so these values win. GIT_CONFIG_GLOBAL is
// deliberately left alone: the user's safe.directory settings live there.
var hardenedGitEnv = []string{
	"GIT_NO_REPLACE_OBJECTS=1",
	"GIT_CONFIG_NOSYSTEM=1",
	"GIT_TERMINAL_PROMPT=0",
	"GIT_PAGER=cat",
	// V1: never fetch a missing object from the scanned repository's
	// promisor remote (git 2.45+). GIT_ALLOW_PROTOCOL set to the empty list
	// allows no transport at all and, unlike -c protocol.allow=never,
	// overrides a repository's own protocol.<name>.allow=always, so it also
	// covers older git.
	"GIT_NO_LAZY_FETCH=1",
	"GIT_ALLOW_PROTOCOL=",
	"LC_ALL=C",
}

// inheritedGitEnvDenied are inherited variables that would point git at
// another repository, object store or config than dir's, or rewrite its
// history (S2). GIT_CONFIG_KEY_<n> and GIT_CONFIG_VALUE_<n> go by prefix.
var inheritedGitEnvDenied = map[string]bool{
	"GIT_DIR":                          true,
	"GIT_WORK_TREE":                    true,
	"GIT_INDEX_FILE":                   true,
	"GIT_OBJECT_DIRECTORY":             true,
	"GIT_ALTERNATE_OBJECT_DIRECTORIES": true,
	"GIT_COMMON_DIR":                   true,
	"GIT_NAMESPACE":                    true,
	"GIT_CEILING_DIRECTORIES":          true,
	"GIT_DISCOVERY_ACROSS_FILESYSTEM":  true,
	"GIT_CONFIG":                       true,
	"GIT_CONFIG_COUNT":                 true,
	"GIT_CONFIG_PARAMETERS":            true,
	"GIT_REPLACE_REF_BASE":             true,
	"GIT_NO_REPLACE_OBJECTS":           true,
	"GIT_GRAFT_FILE":                   true,
	"GIT_SHALLOW_FILE":                 true,
	"GIT_QUARANTINE_PATH":              true,
	"GIT_PREFIX":                       true,
}

// inheritedGitEnv returns os.Environ() without inheritedGitEnvDenied. HOME,
// PATH and GIT_CONFIG_GLOBAL/GIT_CONFIG_SYSTEM/GIT_CONFIG_NOSYSTEM are kept.
func inheritedGitEnv() []string {
	env := os.Environ()
	kept := make([]string, 0, len(env)+len(hardenedGitEnv))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		name = strings.ToUpper(name) // Windows names are case-insensitive
		if inheritedGitEnvDenied[name] ||
			strings.HasPrefix(name, "GIT_CONFIG_KEY_") ||
			strings.HasPrefix(name, "GIT_CONFIG_VALUE_") {
			continue
		}
		kept = append(kept, kv)
	}
	return kept
}

// hardenedGit returns a git command for dir with the hardening flags placed
// before the caller's arguments.
func hardenedGit(ctx context.Context, dir string, args ...string) *exec.Cmd {
	argv := make([]string, 0, len(hardenedGitConfig)+len(args))
	argv = append(argv, hardenedGitConfig...)
	argv = append(argv, args...)
	// #nosec G204 -- constant program, no shell; arguments are built from constants, never from user-controlled options.
	cmd := exec.CommandContext(ctx, "git", argv...)
	cmd.Dir = dir
	cmd.Env = append(inheritedGitEnv(), hardenedGitEnv...)
	return cmd
}

// limitedBuffer keeps the first limit bytes written to it and discards the
// rest, so a chatty stderr cannot grow memory without bound.
type limitedBuffer struct {
	buf   []byte
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string { return string(b.buf) }

// nulReader splits a stream into NUL-terminated tokens without copying in the
// common case. A token longer than max is consumed and reported as overlong
// instead of being returned (SEC-9).
type nulReader struct {
	r       *bufio.Reader
	scratch []byte
	max     int
}

func newNulReader(r io.Reader, bufSize, max int) *nulReader {
	return &nulReader{r: bufio.NewReaderSize(r, bufSize), max: max}
}

// next returns the next token without its terminator. The slice is valid only
// until the following call. A final token with no terminator is returned
// before io.EOF.
func (z *nulReader) next() (tok []byte, overlong bool, err error) {
	b, err := z.r.ReadSlice(0)
	switch {
	case err == nil:
		b = b[:len(b)-1]
		return b, len(b) > z.max, nil
	case errors.Is(err, io.EOF):
		if len(b) == 0 {
			return nil, false, io.EOF
		}
		return b, len(b) > z.max, nil
	case !errors.Is(err, bufio.ErrBufferFull):
		return nil, false, err
	}
	return z.long(b)
}

// long assembles a token that did not fit in the bufio buffer, keeping at
// most max bytes of it.
func (z *nulReader) long(first []byte) ([]byte, bool, error) {
	z.scratch = append(z.scratch[:0], first...)
	overlong := len(z.scratch) > z.max
	for {
		b, err := z.r.ReadSlice(0)
		end := err == nil || errors.Is(err, io.EOF)
		if err == nil {
			b = b[:len(b)-1]
		}
		if !overlong {
			if len(z.scratch)+len(b) > z.max {
				overlong = true
			} else {
				z.scratch = append(z.scratch, b...)
			}
		}
		if end {
			if overlong {
				z.scratch = z.scratch[:0]
				return nil, true, nil
			}
			return z.scratch, false, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, false, err
		}
	}
}
