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
// detect the examples they document. 19 rules remain of the 533 carrying examples.
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
// the 51 original failures found when this test was written, only 8 were regex misses;
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

// ---------------------------------------------------------------------------
// Negative-examples guard (LAB-7152)
// ---------------------------------------------------------------------------

// negativeExampleBaseline records which of a rule's negative examples wrongly
// produce a match, and at which stage.
//
// regexOnly: the regex matches but filterMatches drops the match (filter saves us).
// full:      the negative example survives the full pipeline -- a real false positive.
type negativeExampleBaseline struct {
	regexOnly []int // indices where regex matches but filterMatches drops them
	full      []int // indices where the negative example fully matches (regex + filter)
	total     int   // len(rule.NegativeExamples) when this baseline was taken
}

// knownNegativeExampleFailures is the burn-down list for LAB-7152: rules whose
// negative examples wrongly produce a match. 36 rules remain of the 86 carrying
// negative examples.
//
// TO FIX A RULE, DELETE ITS LINE HERE. TestRuleNegativeExamples_KnownFailuresMatchBaseline
// fails if a listed rule's failures no longer match exactly, so the list cannot
// rot and a fixed rule cannot quietly stop being guarded.
//
// Each failure is one of two things:
//   - regexOnly: the regex is too broad but the post-filter catches it -- the
//     regex could be tightened, but the pipeline result is correct
//   - full: the negative example survives the full pipeline -- a live false
//     positive that needs a rule fix (tighten pattern or add constraints)
var knownNegativeExampleFailures = map[string]negativeExampleBaseline{
	"kingfisher.dbconn.perl.1":       {regexOnly: nil, full: []int{2}, total: 3},
	"kingfisher.dbconn.ruby.1":       {regexOnly: nil, full: []int{2}, total: 3},
	"kingfisher.dotnet.connstring.2": {regexOnly: []int{1}, full: nil, total: 2},
	"kingfisher.gcp.1":               {regexOnly: []int{0}, full: nil, total: 1},
	"kingfisher.gcp.3":               {regexOnly: []int{0}, full: nil, total: 2},
	"kingfisher.gpp.1":               {regexOnly: []int{1}, full: nil, total: 3},
	"kingfisher.powershell.1":        {regexOnly: nil, full: []int{2}, total: 3},
	"kingfisher.powershell.2":        {regexOnly: nil, full: []int{2}, total: 3},
	"kingfisher.rabbitmq.1":          {regexOnly: []int{1}, full: nil, total: 2},
	"np.appcenter.1":                 {regexOnly: []int{2}, full: nil, total: 3},
	"np.azure.5":                     {regexOnly: []int{4, 5}, full: nil, total: 6},
	"np.azure.8":                     {regexOnly: []int{0, 6, 7}, full: nil, total: 8},
	"np.azure.9":                     {regexOnly: nil, full: []int{0, 1}, total: 2},
	"np.browserstack.1":              {regexOnly: nil, full: []int{2}, total: 3},
	"np.ccn.1":                       {regexOnly: []int{0, 1, 2, 3}, full: nil, total: 4},
	"np.ccn.2":                       {regexOnly: []int{0, 1}, full: nil, total: 2},
	"np.ccn.3":                       {regexOnly: []int{0, 1}, full: nil, total: 2},
	"np.ccn.4":                       {regexOnly: []int{0, 1}, full: nil, total: 2},
	"np.cypress.1":                   {regexOnly: nil, full: []int{2}, total: 3},
	"np.delighted.1":                 {regexOnly: []int{2}, full: nil, total: 3},
	"np.grafana.1":                   {regexOnly: nil, full: []int{0, 1}, total: 2},
	"np.grafana.2":                   {regexOnly: nil, full: []int{0}, total: 2},
	"np.grafana.3":                   {regexOnly: nil, full: []int{1}, total: 3},
	"np.helpscout.1":                 {regexOnly: nil, full: []int{2}, total: 3},
	"np.html.1":                      {regexOnly: []int{2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14}, full: nil, total: 16},
	"np.iterable.1":                  {regexOnly: []int{2}, full: nil, total: 4},
	"np.jamf.1":                      {regexOnly: []int{2}, full: nil, total: 7},
	"np.keenio.1":                    {regexOnly: nil, full: []int{2}, total: 4},
	"np.lokalise.1":                  {regexOnly: []int{2}, full: nil, total: 3},
	"np.pendo.1":                     {regexOnly: []int{2}, full: nil, total: 3},
	"np.redis.1":                     {regexOnly: []int{0, 3}, full: nil, total: 4},
	"np.slack.8":                     {regexOnly: nil, full: []int{2}, total: 3},
	"np.spotify.1":                   {regexOnly: []int{2}, full: nil, total: 3},
	"np.wakatime.1":                  {regexOnly: []int{1}, full: nil, total: 3},
	"np.wakatime.2":                  {regexOnly: nil, full: []int{1}, total: 3},
	"np.zendesk.1":                   {regexOnly: nil, full: []int{2}, total: 3},
}

// negativeExampleOutcome reports which of a rule's negative examples wrongly
// produce a match, and at which stage.
func negativeExampleOutcome(t *testing.T, r *types.Rule) (regexOnly, fullMatch []int) {
	t.Helper()
	m, err := NewPortableRegexpWithTimeout([]*types.Rule{r}, 0, nil, 5*time.Second)
	if err != nil {
		t.Fatalf("construct matcher for rule %q: %v", r.ID, err)
	}
	for i, ex := range r.NegativeExamples {
		ms, err := m.Match([]byte(ex))
		if err != nil || len(ms) == 0 {
			continue
		}
		if len(filterMatches(ms, map[string]*types.Rule{r.ID: r})) == 0 {
			regexOnly = append(regexOnly, i)
		} else {
			fullMatch = append(fullMatch, i)
		}
	}
	return regexOnly, fullMatch
}

func rulesWithNegativeExamples(t *testing.T) []*types.Rule {
	t.Helper()
	all, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)
	var out []*types.Rule
	for _, r := range all {
		if len(r.NegativeExamples) > 0 {
			out = append(out, r)
		}
	}
	require.NotEmpty(t, out)
	return out
}

// No rule outside the burn-down list may match any of its own negative examples.
//
// Like the positive-examples guard, this runs the full pipeline -- regex AND
// filterMatches. A negative example that only matches at the regex stage (but
// is dropped by the filter) is still recorded: the regex is broader than it
// needs to be, and the filter is doing work the pattern should handle.
func TestRuleNegativeExamples_NoRuleMatchesItsOwnNegativeExamples(t *testing.T) {
	for _, r := range rulesWithNegativeExamples(t) {
		if _, known := knownNegativeExampleFailures[r.ID]; known {
			continue
		}
		ro, fm := negativeExampleOutcome(t, r)
		if len(ro) > 0 || len(fm) > 0 {
			t.Errorf("rule %q matches its own negative examples (regex-only indices %v, full-pipeline indices %v).\n"+
				"Either the negative example is wrong, or the rule is too broad. "+
				"If this is a pre-existing failure being surfaced, add a baseline to knownNegativeExampleFailures.",
				r.ID, ro, fm)
		}
	}
}

// A listed rule must fail EXACTLY the negative examples its baseline records.
func TestRuleNegativeExamples_KnownFailuresMatchBaseline(t *testing.T) {
	byID := map[string]*types.Rule{}
	for _, r := range rulesWithNegativeExamples(t) {
		byID[r.ID] = r
	}
	for id, want := range knownNegativeExampleFailures {
		r, ok := byID[id]
		if !ok {
			t.Errorf("knownNegativeExampleFailures lists %q, which no longer exists or has no negative examples — remove the entry", id)
			continue
		}
		if len(r.NegativeExamples) != want.total {
			t.Errorf("rule %q now has %d negative examples, baseline recorded %d — indices have shifted, re-baseline the entry",
				id, len(r.NegativeExamples), want.total)
			continue
		}
		ro, fm := negativeExampleOutcome(t, r)
		assert.Equalf(t, want.regexOnly, ro,
			"rule %q: regex-only failures changed. If negative examples were fixed, delete or update the entry; "+
				"if a passing negative example regressed, that is a new false positive.", id)
		assert.Equalf(t, want.full, fm,
			"rule %q: full-pipeline failures changed. If negative examples were fixed, delete or update the entry; "+
				"if a passing negative example regressed, that is a new false positive.", id)
		if len(ro) == 0 && len(fm) == 0 {
			t.Errorf("rule %q no longer matches any of its negative examples — delete its line from knownNegativeExampleFailures", id)
		}
	}
}
