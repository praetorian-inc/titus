package enum

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
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
	"-c", "core.hooksPath=/dev/null",
}

// hardenedGitEnv is appended after the inherited environment; exec keeps the
// last duplicate, so these values win. GIT_CONFIG_GLOBAL is deliberately left
// alone: the user's safe.directory settings live there.
var hardenedGitEnv = []string{
	"GIT_NO_REPLACE_OBJECTS=1",
	"GIT_CONFIG_NOSYSTEM=1",
	"GIT_TERMINAL_PROMPT=0",
	"GIT_PAGER=cat",
	"LC_ALL=C",
}

// hardenedGit returns a git command for dir with the hardening flags placed
// before the caller's arguments.
func hardenedGit(ctx context.Context, dir string, args ...string) *exec.Cmd {
	argv := make([]string, 0, len(hardenedGitConfig)+len(args))
	argv = append(argv, hardenedGitConfig...)
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, "git", argv...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), hardenedGitEnv...)
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
