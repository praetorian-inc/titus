package commitlink

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// suffixProbe records what a test-only suffix builder is handed.
type suffixProbe struct {
	called           bool
	label, path, sha string
}

// registerProbe registers a test-only suffix and removes it afterwards so it
// never reaches other tests. Not parallel: it mutates the package registry.
func registerProbe(t *testing.T, suffix string) *suffixProbe {
	t.Helper()
	p := &suffixProbe{}
	registerSuffix(suffix, func(label, path, sha string) string {
		p.called = true
		p.label, p.path, p.sha = label, path, sha
		return "https://forge.test-only.invalid/" + label + "/" + path + "/commit/" + sha
	})
	t.Cleanup(func() { delete(suffixes, suffix) })
	return p
}

func TestRegisterSuffix_MatchPassesLabelPathAndSHA(t *testing.T) {
	p := registerProbe(t, ".suffix.test-only.invalid")
	got := URL(gitOcc("acme.suffix.test-only.invalid", "acme.suffix.test-only.invalid/group/repo", sha40))
	assert.Equal(t, "https://forge.test-only.invalid/acme/group/repo/commit/"+sha40, got)
	assert.Equal(t, "acme", p.label)
	assert.Equal(t, "group/repo", p.path)
	assert.Equal(t, sha40, p.sha)
}

// Only a host that is exactly "<one label><suffix>" matches.
func TestRegisterSuffix_OnlyOneLabelBeforeTheSuffixMatches(t *testing.T) {
	p := registerProbe(t, ".suffix.test-only.invalid")
	for name, host := range map[string]string{
		"empty label":            "suffix.test-only.invalid",
		"two labels":             "a.b.suffix.test-only.invalid",
		"label glued to suffix":  "evilsuffix.test-only.invalid",
		"suffix is not the end":  "acme.suffix.test-only.invalid.evil",
		"different tld":          "acme.suffix.test-only.example",
		"unrelated host":         "evil.com",
		"suffix only as a label": "suffix.test-only.invalid.acme.com",
	} {
		t.Run(name, func(t *testing.T) {
			p.called = false
			assert.Equal(t, "", URL(gitOcc(host, host+"/group/repo", sha40)))
			assert.False(t, p.called, "builder is never reached for %s", host)
		})
	}
}

// A host registered exactly takes precedence over a suffix that also matches.
func TestRegisterSuffix_ExactHostWinsOverSuffix(t *testing.T) {
	const host = "exact.suffix.test-only.invalid"
	p := registerProbe(t, ".suffix.test-only.invalid")
	register(host, func(path, sha string) string { return "https://exact.test-only.invalid/" + path + "/" + sha })
	t.Cleanup(func() { delete(hosts, host) })

	assert.Equal(t, "https://exact.test-only.invalid/group/repo/"+sha40, URL(gitOcc(host, host+"/group/repo", sha40)))
	assert.False(t, p.called, "suffix builder is not consulted when the exact host matches")
	assert.Equal(t, "https://forge.test-only.invalid/other/group/repo/commit/"+sha40,
		URL(gitOcc("other.suffix.test-only.invalid", "other.suffix.test-only.invalid/group/repo", sha40)),
		"a sibling host still falls through to the suffix")
}

// The suffix path shares the core's checks: the builder is never handed an
// unsafe path or a commit that is not full lowercase hex.
func TestRegisterSuffix_CoreValidationStillApplies(t *testing.T) {
	const host = "acme.suffix.test-only.invalid"
	p := registerProbe(t, ".suffix.test-only.invalid")
	for name, in := range map[string]struct{ repo, sha string }{
		"dot-dot":           {host + "/group/..", sha40},
		"space":             {host + "/group/my repo", sha40},
		"escape sequence":   {host + "/group/re\x1b[2Jpo", sha40},
		"repository prefix": {"other.test-only.invalid/group/repo", sha40},
		"uppercase commit":  {host + "/group/repo", strings.ToUpper(sha40)},
		"short commit":      {host + "/group/repo", sha40[:7]},
		"no commit":         {host + "/group/repo", ""},
	} {
		t.Run(name, func(t *testing.T) {
			p.called = false
			assert.Equal(t, "", URL(gitOcc(host, in.repo, in.sha)))
			assert.False(t, p.called)
		})
	}

	wt := gitOcc(host, host+"/group/repo", sha40)
	wt.WorkingTree = true
	p.called = false
	assert.Equal(t, "", URL(wt))
	assert.False(t, p.called, "working tree never reaches the builder")
}

func TestRegisterSuffix_BuilderMayRefuseItsOwnShape(t *testing.T) {
	const suffix = ".refuses.test-only.invalid"
	registerSuffix(suffix, func(label, path, sha string) string { return "" })
	t.Cleanup(func() { delete(suffixes, suffix) })
	assert.Equal(t, "", URL(gitOcc("acme.refuses.test-only.invalid", "acme.refuses.test-only.invalid/a/b", sha40)))
}

func TestRegisterSuffix_PanicsOnEmptySuffix(t *testing.T) {
	before := len(suffixes)
	assert.Panics(t, func() {
		registerSuffix("", func(string, string, string) string { return "x" })
	})
	assert.Len(t, suffixes, before, "a rejected registration must not change the registry")
}

func TestRegisterSuffix_PanicsOnDuplicateSuffix(t *testing.T) {
	const suffix = ".dup.test-only.invalid"
	registerProbe(t, suffix)
	before := len(suffixes)
	assert.Panics(t, func() {
		registerSuffix(suffix, func(string, string, string) string { return "other" })
	})
	assert.Len(t, suffixes, before, "a rejected registration must not change the registry")
	assert.Equal(t, "https://forge.test-only.invalid/acme/g/r/commit/"+sha40,
		URL(gitOcc("acme.dup.test-only.invalid", "acme.dup.test-only.invalid/g/r", sha40)), "original builder survives")
}

func TestRegisteredSuffixTestHostsDoNotLeak(t *testing.T) {
	for _, s := range []string{".suffix.test-only.invalid", ".refuses.test-only.invalid", ".dup.test-only.invalid"} {
		assert.NotContains(t, suffixes, s)
	}
}
