package explore

import (
	"errors"
	"strings"
	"testing"
)

// ENG-9178 review: a failed location load says so, with the sanitized error,
// instead of showing "Locations 0:".
func TestDetailsPane_LocationsErrRendersSanitizedError(t *testing.T) {
	m := matchWith(1)
	m.LocationsErr = errors.New("database is locked\x1b]0;pwn\x07\x1b[2J")
	dp := newTestPane()
	dp.setFinding(&findingRow{RuleName: "r", RuleID: "id", Matches: []*matchRow{m}})

	out := dp.View()
	assertNoTerminalControl(t, "LocationsErr", out)
	plain := stripAnsi(out)
	if !strings.Contains(plain, "Locations unavailable:") {
		t.Errorf("no %q heading:\n%s", "Locations unavailable:", plain)
	}
	if !strings.Contains(plain, `database is locked\x1b]0;pwn\x07\x1b[2J`) {
		t.Errorf("sanitized error text missing:\n%s", plain)
	}
	if strings.Contains(plain, "Locations 0:") {
		t.Errorf("failed load shown as zero locations:\n%s", plain)
	}
}
