//go:build linux && !wasm && cgo && vectorscan

package matcher

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// residentBytes reads RSS from /proc/self/statm. A leaked scratch is a C
// allocation, so it is invisible to runtime.MemStats and only the OS view
// shows it.
func residentBytes(t *testing.T) int64 {
	t.Helper()

	raw, err := os.ReadFile("/proc/self/statm")
	require.NoError(t, err)

	fields := strings.Fields(string(raw))
	require.GreaterOrEqual(t, len(fields), 2)

	pages, err := strconv.ParseInt(fields[1], 10, 64)
	require.NoError(t, err)

	return pages * int64(os.Getpagesize())
}

// scratchLeakRules builds a rule set large enough that a dropped scratch is
// visible in RSS. The rule count is load-bearing, not incidental: scratch size
// scales with the compiled database, and at one rule a scratch is ~3 KB, so the
// leaking implementation grew under 5 MB over this loop and an earlier version
// of this test passed against the very bug it exists to catch.
func scratchLeakRules(n int) []*types.Rule {
	rules := make([]*types.Rule, 0, n)
	for i := range n {
		rules = append(rules, &types.Rule{
			ID:      fmt.Sprintf("scratch-leak-rule-%d", i),
			Name:    fmt.Sprintf("Scratch Leak Fixture %d", i),
			Pattern: fmt.Sprintf(`(?i)fixture%dkey[_-]?(?P<token>[A-Za-z0-9]{%d,40})`, i, 16+i%8),
		})
	}

	return rules
}

// TestScratchPool_DoesNotLeakAcrossGC is the regression test for the leak.
// The pool used to be a sync.Pool, which drops its entries on every GC; each
// dropped scratch took an hs_clone_scratch allocation with it, so RSS climbed
// in proportion to GC count while the Go heap stayed flat. Scanning with a GC
// between every scan is the worst case for that. The rule count is what makes
// the assertion below meaningful: too few rules and a dropped scratch is too
// small to separate from noise.
func TestScratchPool_DoesNotLeakAcrossGC(t *testing.T) {
	const (
		leakFixtureRules = 500
		scans            = 2000
		maxGrowth        = 32 << 20

		// `scans` dropped scratches have to outweigh maxGrowth for the
		// assertion below to be able to fail at all. Double that for headroom.
		minScratchSize = 2 * maxGrowth / scans
	)

	rules := scratchLeakRules(leakFixtureRules)

	m, err := NewVectorscan(rules, 0, nil)
	require.NoError(t, err)

	defer m.Close()

	// Guard the fixture, not just the behavior: without this, shrinking the
	// rule set turns the assertion below into a silent no-op.
	scratchSize, err := m.scratch.Size()
	require.NoError(t, err)
	require.Greater(t, scratchSize, minScratchSize,
		"fixture too small to detect the leak: one scratch is %d B, so %d of them stay under the %d B bound this test asserts",
		scratchSize, scans, maxGrowth)

	content := []byte("no secret here, just text to scan repeatedly")

	// Warm up so the database and the first scratch are already resident.
	for range 50 {
		_, err := m.Match(content)
		require.NoError(t, err)
	}

	runtime.GC()
	before := residentBytes(t)

	for range scans {
		_, err := m.Match(content)
		require.NoError(t, err)

		runtime.GC()
	}

	runtime.GC()
	growth := residentBytes(t) - before

	// Leaking one scratch per GC cost hundreds of MB over this loop. The
	// bound is deliberately loose: it only has to separate "bounded" from
	// "grows with GC count".
	assert.Less(t, growth, int64(maxGrowth),
		"RSS grew %d bytes over %d scans, which means scratches are being dropped rather than freed",
		growth, scans)
}
