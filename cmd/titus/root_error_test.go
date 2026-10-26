package main

import (
	"bytes"
	"strings"
	"testing"
)

// runRoot runs Execute with args and returns the error and everything
// written. Out and Err share one buffer: with neither set, cobra sends both
// the error line and the usage to stderr, so one stream is what a user sees.
func runRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})
	err := Execute()
	return buf.String(), err
}

const usageHint = "for usage."

// R6-2: reportError must print what cobra prints. A flag error is followed
// by the usage of the command that rejected it, runnable or not; only an
// unknown command (a lookup error) gets the help hint instead.
func TestReportError_MatchesCobraUsageOrHint(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		errLine   string
		wantUsage bool
	}{
		{"unknown flag on the enum group", []string{"enum", "--bogus"}, "Error: unknown flag: --bogus\n", true},
		{"unknown flag on runnable scan", []string{"scan", "--nope"}, "Error: unknown flag: --nope\n", true},
		{"unknown command", []string{"bogus"}, `Error: unknown command "bogus" for "titus"` + "\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := runRoot(t, c.args...)
			if err == nil {
				t.Fatalf("Execute(%q) returned nil, want an error (output %q)", c.args, out)
			}
			if !strings.HasPrefix(out, c.errLine) {
				t.Fatalf("output = %q, want it to start with %q", out, c.errLine)
			}
			rest := out[len(c.errLine):]
			if c.wantUsage {
				if !strings.HasPrefix(rest, "Usage:") {
					t.Errorf("after the error line: %q, want the usage (\"Usage:\")", rest)
				}
				if strings.Contains(out, usageHint) {
					t.Errorf("output = %q, want the usage, not the help hint", out)
				}
				return
			}
			wantHint := "Run 'titus --help' " + usageHint + "\n"
			if rest != wantHint {
				t.Errorf("after the error line: %q, want only %q", rest, wantHint)
			}
		})
	}
}

// O3 / R6-2: a flag name is user input that lands in the error message.
// Control bytes in it reach the terminal escaped, never raw, and the error
// value itself is unchanged.
func TestReportError_EscapesControlBytesInFlagError(t *testing.T) {
	out, err := runRoot(t, "enum", "--bogus\x1b[31mred")
	if err == nil {
		t.Fatalf("Execute returned nil, want an error (output %q)", out)
	}
	if !strings.Contains(err.Error(), "\x1b[31m") {
		t.Errorf("err = %q, want the raw flag name in the error value", err)
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("output = %q, carries a raw ESC byte", out)
	}
	if want := `Error: unknown flag: --bogus\x1b[31mred` + "\n"; !strings.HasPrefix(out, want) {
		t.Errorf("output = %q, want it to start with %q", out, want)
	}
}
