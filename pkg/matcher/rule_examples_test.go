// This guard deliberately runs under -race as well as normally.
//
// It carried //go:build !race until LAB-6097. np.phpmailer.1 nested quantifiers
// over .*, which cost ~3s per match normally and exceeded 30s under -race,
// where instrumentation is roughly an order of magnitude slower. Excluding the
// guard was the wrong way round: the slowness was the bug, not the test.
//
// Running under -race now earns something specific. A pattern that reintroduces
// catastrophic backtracking will blow the match timeout there long before it
// does in a normal run, so the Race Detector job doubles as a cheap budget
// check on rule patterns -- no brittle timing assertion required.

package matcher

import (
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exampleBaseline records exactly which of a rule's examples are known to fail,
// by index, and at which stage.
//
// Indices rather than counts, for the same reason the map is keyed by rule ID
// rather than holding a total: a count lets a fixed example be silently traded
// for a newly broken one. total is recorded too, so adding or removing an
// example -- which shifts every index after it -- forces a re-baseline instead
// of quietly invalidating the entries.
type exampleBaseline struct {
	regex  []int // indices whose example the regex never matches
	filter []int // indices matched by the regex, then dropped by filterMatches
	total  int   // len(rule.Examples) when this baseline was taken
}

// knownExampleFailures is the burn-down list for LAB-6096: rules that cannot
// detect the examples they document. 51 rules of the 533 carrying examples.
//
// TO FIX A RULE, DELETE ITS LINE HERE. TestRuleExamples_KnownFailuresMatchBaseline
// fails if a listed rule's failures no longer match exactly, so the list cannot
// rot and a fixed rule cannot quietly stop being guarded.
//
// Each failure is one of two things, and they need opposite fixes:
//   - the example does not represent a real credential -> fix the example
//   - the rule's constraints exclude the real credential format -> fix the
//     rule, and treat it as a live detection gap
//
// Do NOT bulk-relax pattern_requirements to clear these. Those constraints
// exist to suppress false positives; loosening them blindly trades a
// false-negative problem for a false-positive one.
var knownExampleFailures = map[string]exampleBaseline{
	"kingfisher.ai21studio.1":   {regex: nil, filter: []int{0, 1, 2}, total: 3},
	"kingfisher.anypoint.1":     {regex: nil, filter: []int{0}, total: 1},
	"kingfisher.asana.1":        {regex: nil, filter: []int{0, 1}, total: 2},
	"kingfisher.azure.devops.1": {regex: nil, filter: []int{0}, total: 2},
	"kingfisher.cloudflare.1":   {regex: nil, filter: []int{0, 1}, total: 2},
	"kingfisher.cloudflare.2":   {regex: nil, filter: []int{0, 1}, total: 2},
	"kingfisher.contentful.1":   {regex: []int{1}, filter: nil, total: 3},
	"kingfisher.discord.3":      {regex: nil, filter: []int{0, 1}, total: 2},
	"kingfisher.gocardless.1":   {regex: nil, filter: []int{1}, total: 2},
	"kingfisher.jira.1":         {regex: nil, filter: []int{0, 1}, total: 2},
	"kingfisher.privkey.1":      {regex: nil, filter: []int{0}, total: 1},
	"kingfisher.privkey.2":      {regex: nil, filter: []int{4}, total: 5},
	"kingfisher.rabbitmq.1":     {regex: nil, filter: []int{1, 3}, total: 4},
	"kingfisher.recaptcha.1":    {regex: nil, filter: []int{0, 1, 2}, total: 3},
	"kingfisher.runway.1":       {regex: nil, filter: []int{0, 1, 2, 3}, total: 4},
	"kingfisher.scraperapi.1":   {regex: nil, filter: []int{1}, total: 2},
	"kingfisher.sendbird.2":     {regex: nil, filter: []int{0}, total: 1},
	"kingfisher.vercel.1":       {regex: nil, filter: []int{0, 1, 3}, total: 4},
	"np.redis.1":                {regex: []int{3}, filter: nil, total: 4},
}

// exampleOutcome reports which of a rule's examples fail, and at which stage.
func exampleOutcome(t *testing.T, r *types.Rule) (regexFails, filterFails []int) {
	t.Helper()
	// 5s rather than the 500ms production default. The question here is whether
	// a rule CAN detect its example, not whether it does so quickly on a loaded
	// CI runner -- a guard that passes on fast machines and fails on slow ones is
	// worse than no guard. 5s is the matcher's own fallback timeout, so it is a
	// generous ceiling rather than an arbitrary one.
	m, err := NewPortableRegexpWithTimeout([]*types.Rule{r}, 0, nil, 5*time.Second)
	if err != nil {
		for i := range r.Examples {
			regexFails = append(regexFails, i)
		}
		return regexFails, nil
	}
	for i, ex := range r.Examples {
		ms, err := m.Match([]byte(ex))
		if err != nil || len(ms) == 0 {
			regexFails = append(regexFails, i)
			continue
		}
		if len(filterMatches(ms, map[string]*types.Rule{r.ID: r})) == 0 {
			filterFails = append(filterFails, i)
		}
	}
	return regexFails, filterFails
}

func rulesWithExamples(t *testing.T) []*types.Rule {
	t.Helper()
	all, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)
	var out []*types.Rule
	for _, r := range all {
		if len(r.Examples) > 0 {
			out = append(out, r)
		}
	}
	require.NotEmpty(t, out)
	return out
}

// Every rule not on the burn-down list must detect all of its own examples.
//
// This runs the FULL pipeline -- regex AND the entropy / pattern_requirements
// post-filters -- because most failures do not happen at the regex stage. Of
// the 51 failures found when this test was written, only 8 were regex misses;
// the other 43 matched and were then dropped by filterMatches. A regex-only
// test reports 8 and looks reassuring.
func TestRuleExamples_AllRulesDetectTheirOwnExamples(t *testing.T) {
	for _, r := range rulesWithExamples(t) {
		if _, known := knownExampleFailures[r.ID]; known {
			continue
		}
		rx, fl := exampleOutcome(t, r)
		if len(rx) > 0 || len(fl) > 0 {
			t.Errorf("rule %q fails its own examples (regex-unmatched indices %v, post-filtered indices %v).\n"+
				"Either the example is not a real credential, or the rule's pattern/requirements exclude it. "+
				"If this is a pre-existing failure being surfaced, add a baseline to knownExampleFailures.",
				r.ID, rx, fl)
		}
	}
}

// A listed rule must fail EXACTLY the examples its baseline records.
//
// Allowlisting a rule ID alone would drop every one of its examples from
// coverage, including the ones that currently pass -- kingfisher.jdbc.1 fails 3
// of 4. Comparing exact indices keeps the passing example guarded, and means a
// fixed failure cannot be exchanged for a new one without the test noticing.
func TestRuleExamples_KnownFailuresMatchBaseline(t *testing.T) {
	byID := map[string]*types.Rule{}
	for _, r := range rulesWithExamples(t) {
		byID[r.ID] = r
	}
	for id, want := range knownExampleFailures {
		r, ok := byID[id]
		if !ok {
			t.Errorf("knownExampleFailures lists %q, which no longer exists or has no examples — remove the entry", id)
			continue
		}
		if len(r.Examples) != want.total {
			t.Errorf("rule %q now has %d examples, baseline recorded %d — indices have shifted, re-baseline the entry",
				id, len(r.Examples), want.total)
			continue
		}
		rx, fl := exampleOutcome(t, r)
		assert.Equalf(t, want.regex, rx,
			"rule %q: regex-stage failures changed. If examples were fixed, delete or update the entry; "+
				"if a passing example regressed, that is a new detection gap.", id)
		assert.Equalf(t, want.filter, fl,
			"rule %q: post-filter failures changed. If examples were fixed, delete or update the entry; "+
				"if a passing example regressed, that is a new detection gap.", id)
		if len(rx) == 0 && len(fl) == 0 {
			t.Errorf("rule %q now detects all its examples — delete its line from knownExampleFailures", id)
		}
	}
}
