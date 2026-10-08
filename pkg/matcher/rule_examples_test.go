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
	"fmt"
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
// coverage, including the ones that currently pass. Comparing exact indices
// keeps the passing example guarded, and means a fixed failure cannot be
// exchanged for a new one without the test noticing.
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
// negative examples wrongly produce a match. 38 rules remain of the 164 carrying
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
	"kingfisher.jdbc.2":              {regexOnly: []int{2}, full: nil, total: 3},
	"kingfisher.jdbc.3":              {regexOnly: []int{2}, full: nil, total: 3},
	"kingfisher.powershell.1":        {regexOnly: nil, full: []int{2}, total: 3},
	"kingfisher.powershell.2":        {regexOnly: nil, full: []int{2}, total: 3},
	"kingfisher.rabbitmq.1":          {regexOnly: []int{1, 2, 3}, full: nil, total: 4},
	"np.appcenter.1":                 {regexOnly: []int{2}, full: nil, total: 3},
	"np.azure.5":                     {regexOnly: []int{4, 5}, full: nil, total: 6},
	"np.azure.8":                     {regexOnly: []int{0, 6, 7}, full: nil, total: 8},
	"np.azure.9":                     {regexOnly: nil, full: []int{0, 1}, total: 2},
	"np.browserstack.1":              {regexOnly: nil, full: []int{2}, total: 3},
	"np.ccn.1":                       {regexOnly: []int{0, 1, 2, 3, 4}, full: nil, total: 5},
	"np.ccn.2":                       {regexOnly: []int{0, 1, 2}, full: nil, total: 3},
	"np.ccn.3":                       {regexOnly: []int{0, 1, 2}, full: nil, total: 3},
	"np.ccn.4":                       {regexOnly: []int{0, 1, 2}, full: nil, total: 3},
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
		if err != nil {
			// A negative example the matcher cannot evaluate is not a pass.
			t.Fatalf("rule %q: match negative_examples[%d]: %v", r.ID, i, err)
		}
		if len(ms) == 0 {
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

// loadBuiltinRule returns one built-in rule by ID.
func loadBuiltinRule(t *testing.T, id string) *types.Rule {
	t.Helper()
	all, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err, "loading builtin rules")
	for _, r := range all {
		if r.ID == id {
			return r
		}
	}
	require.FailNowf(t, "rule not found", "no builtin rule with ID %q", id)
	return nil
}

// ruleOutcome runs the FULL pipeline for one rule against one input: the regex
// stage, then the filterMatches post-filters. It reports the surviving count at
// each stage separately so a test can say which stage did (or failed to do) the
// rejecting. Same 5s timeout rationale as exampleOutcome.
func ruleOutcome(t *testing.T, r *types.Rule, input string) (regexMatches, pipelineMatches int) {
	t.Helper()
	m, err := NewPortableRegexpWithTimeout([]*types.Rule{r}, 0, nil, 5*time.Second)
	require.NoErrorf(t, err, "rule %q: building matcher", r.ID)

	ms, err := m.Match([]byte(input))
	require.NoErrorf(t, err, "rule %q: matching input %q", r.ID, input)

	regexMatches = len(ms)
	pipelineMatches = len(filterMatches(ms, map[string]*types.Rule{r.ID: r}))
	return regexMatches, pipelineMatches
}

// awsExampleRuleIDs are the two rules taught to reject AWS
// documentation placeholder key IDs.
var awsExampleRuleIDs = []string{"np.aws.1", "np.aws.6"}

var awsDocPlaceholderKeyIDs = []string{
	"AKIAIOSFODNN7EXAMPLE",
	"ASIAIOSFODNN7EXAMPLE",
	"AIDAIOSFODNN7EXAMPLE",
	"AROAIOSFODNN7EXAMPLE",
	"A3T0IOSFODNN7EXAMPLE",
}

// awsDocPlaceholderSecret is AWS's own published example secret (40 chars).
const awsDocPlaceholderSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

// awsRealSecret is a realistic 40-char secret with no "EXAMPLE" in it, used to
// pair with key IDs that SHOULD be reported.
const awsRealSecret = "ded7db27a4558eea9bbf0bf36e0e8521618f366c"

// awsInputFor wraps a bare key ID into an input shaped for the given rule.
func awsInputFor(ruleID, keyID, secret string) string {
	if ruleID == "np.aws.6" {
		// The separator is 32 characters, inside np.aws.6's 40-char window.
		return fmt.Sprintf("export AWS_ACCESS_KEY_ID='%s'\nexport AWS_SECRET_ACCESS_KEY='%s'\n", keyID, secret)
	}
	return keyID
}

// Documentation placeholder key IDs must survive neither stage, for both rules
// and all five prefix families.
func TestAWSExampleKeys_DocumentationKeysAreNotReported(t *testing.T) {
	require.NotEmpty(t, awsDocPlaceholderKeyIDs)

	for _, ruleID := range awsExampleRuleIDs {
		r := loadBuiltinRule(t, ruleID)
		for _, keyID := range awsDocPlaceholderKeyIDs {
			t.Run(ruleID+"/"+keyID, func(t *testing.T) {
				input := awsInputFor(ruleID, keyID, awsDocPlaceholderSecret)
				rx, pipeline := ruleOutcome(t, r, input)

				assert.Zerof(t, rx, "rule %q: pattern matched AWS documentation placeholder key ID %q "+
					"(input %q) -- the EXAMPLE negative lookahead is missing or too narrow", ruleID, keyID, input)
				assert.Zerof(t, pipeline, "rule %q: AWS documentation placeholder key ID %q survived the full "+
					"pipeline (input %q) and would be reported as a credential", ruleID, keyID, input)
			})
		}
	}
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

// awsIgnoreIfContainsSubstringDrop is the reason np.aws.1 drops a key ID whose
// body contains "EXAMPLE" away from the final 7 characters: its
// pattern_requirements.ignore_if_contains: ["EXAMPLE"] is a plain
// case-insensitive substring test on the key_id capture, so position is
// irrelevant at the post-filter. Whether that filter should be narrowed now
// that the precise lookahead exists is out of scope for LAB-6509.
const awsIgnoreIfContainsSubstringDrop = "np.aws.1 pattern_requirements.ignore_if_contains " +
	`["EXAMPLE"] is a substring test on key_id, so it drops any body containing EXAMPLE`

// Real keys, and near-misses that resemble placeholders without being them,
// must still be reported. This is the regression guard against a lookahead that
// swallows more than the documentation IDs.
func TestAWSExampleKeys_RealAndNearMissKeysStillMatch(t *testing.T) {
	cases := []struct {
		name  string
		keyID string
		why   string
		// pipelineDropsFor maps a rule ID to the reason that rule's POST-FILTERS
		// drop this key ID even though its pattern admits it. Absent for every
		// rule that reports the key ID normally.
		pipelineDropsFor map[string]string
	}{
		{name: "real_AKIA", keyID: "AKIADEADBEEFDEADBEEF", why: "ordinary AKIA key, nothing EXAMPLE-like about it"},
		{name: "real_A3T0", keyID: "A3T0ABCDEFGHIJKLMNOP", why: "ordinary A3T-family key"},
		{name: "nearmiss_trailing_Z", keyID: "AKIAIOSFODNN7EXAMPLZ", why: "last 7 chars are EXAMPLZ, not EXAMPLE"},
		{name: "nearmiss_trailing_0", keyID: "AKIAIOSFODNN7EXAMPL0", why: "last 7 chars are EXAMPL0, not EXAMPLE"},
		// The two trailing_* cases above vary the LAST character, so they only prove
		// the lookahead is not keying off a loose "EXAMPLE" substring. These two
		// prove it is positionally anchored to the end of the 16-char body: a
		// mis-written `(?!.*EXAMPLE)` or `(?![A-Z0-9]*EXAMPLE)` passes the first
		// pair while wrongly suppressing real keys that merely contain EXAMPLE
		// earlier.
		{
			name:  "nearmiss_EXAMPLE_at_body_start",
			keyID: "AKIAEXAMPLE123456789",
			why:   "EXAMPLE at the start of the 16-char body, not the end -- the lookahead is anchored to the last 7 characters, so this is a real key",
			pipelineDropsFor: map[string]string{
				"np.aws.1": awsIgnoreIfContainsSubstringDrop,
			},
		},
		{
			name:  "nearmiss_EXAMPLE_mid_body",
			keyID: "AKIA0EXAMPLE12345678",
			why:   "EXAMPLE in the middle of the body -- same reason; guards against a lookahead written as (?![A-Z0-9]*EXAMPLE) or (?!.*EXAMPLE)",
			pipelineDropsFor: map[string]string{
				"np.aws.1": awsIgnoreIfContainsSubstringDrop,
			},
		},
	}

	for _, ruleID := range awsExampleRuleIDs {
		r := loadBuiltinRule(t, ruleID)
		for _, tc := range cases {
			t.Run(ruleID+"/"+tc.name, func(t *testing.T) {
				input := awsInputFor(ruleID, tc.keyID, awsRealSecret)
				rx, pipeline := ruleOutcome(t, r, input)

				// The regex-stage assertion is unconditional: it is what proves the
				// lookahead is positionally anchored to the last 7 characters.
				assert.NotZerof(t, rx, "rule %q: pattern no longer matches key ID %q (%s; input %q) -- "+
					"the EXAMPLE negative lookahead is too broad", ruleID, tc.keyID, tc.why, input)

				if reason, drops := tc.pipelineDropsFor[ruleID]; drops {
					assert.Zerof(t, pipeline, "rule %q: key ID %q survived the post-filters, but %s -- "+
						"so it should have been dropped. If that requirement was narrowed or removed, "+
						"delete this rule's entry from the case's pipelineDropsFor map so it asserts "+
						"NotZero like the rest.", ruleID, tc.keyID, reason)
					return
				}

				assert.NotZerof(t, pipeline, "rule %q: key ID %q (%s; input %q) matched the pattern but was "+
					"dropped by the post-filters and would go unreported", ruleID, tc.keyID, tc.why, input)
			})
		}
	}
}

var jdbcRuleIDs = []string{"kingfisher.jdbc.1", "kingfisher.jdbc.2", "kingfisher.jdbc.3", "kingfisher.jdbc.4"}

func TestNoiseRules_FalsePositiveModesRejectedByPattern(t *testing.T) {
	cases := []struct {
		rules []string
		input string
	}{
		{jdbcRuleIDs, "jdbc:postgresql://pg-primary.db.internal:5432/orders_events"},
		{jdbcRuleIDs, "jdbc:oracle:thin:@ORCL1.db.internal:1590/ORCL1.db.internal"},
		{jdbcRuleIDs, "jdbc:hive2://hive.db.internal:10000/warehouse_raw_qa"},
		{jdbcRuleIDs, "jdbc:sqlserver://sql.proddb.org:1433;databaseName=inventory;integratedSecurity=true"},
		{[]string{"kingfisher.discord.2"}, "sdk_deployment_client.models.remote_gateway_tunnel_options_inner"},
		{[]string{"kingfisher.discord.2"}, "nt_analytics_published.dm_ops.session_contract_daily_fact"},
		{[]string{"kingfisher.discord.2"}, "x9LN8q27pKWSEcN3fN9ptV2gEm.QA7Hyu.rPbXngGYcLWTKv7ZK2dSo9jpBnY"},
		{[]string{"kingfisher.discord.2"}, "Bracket_Steel_BR-XLSR-3.2mm_H5.6mm_ReverseMount_8812034560Bracket"},
		{[]string{"kingfisher.discord.2"}, "kQwe-NR7d2_p5J41nTZk8QLRM3_6Y2B.bsVcmy.wKF428gm2b8PNPl6izTJ_Y8W_-p"},
		{[]string{"kingfisher.plaid.1"}, `"client_id":"64b1f0c2e9a73d5b8c4e2a9d"`},
		{[]string{"kingfisher.plaid.1"}, `client_id = "a1b2c3d4e5f60718293a4b5c"`},
	}
	for _, c := range cases {
		for _, id := range c.rules {
			t.Run(id+"/"+c.input, func(t *testing.T) {
				rx, _ := ruleOutcome(t, loadBuiltinRule(t, id), c.input)
				assert.Zerof(t, rx, "pattern matched %q", c.input)
			})
		}
	}
}

func TestNoiseRules_RealShapesStillDetected(t *testing.T) {
	cases := []struct{ rule, input string }{
		{"kingfisher.jdbc.1", "jdbc:mysql://admin:s3cr3t@prod.internal:3306/inventory"},
		{"kingfisher.jdbc.3", "jdbc:jtds:sqlserver://SQLHOST01:8025;databaseName=APP;prepareSQL=1;userName=APP_READ;password=Qz7vLm2pKe"},
		{"kingfisher.jdbc.2", "jdbc:mysql://10.0.12.34:3306/appdb?user=app_user&password=app_user"},
		// XML-escaped "&amp;password=" carries a literal ";password=", so the
		// semicolon-property rule reports it.
		{"kingfisher.jdbc.3", "spring.datasource.url=jdbc:postgresql://10.20.30.40:5432/warehouse?user=etl_user&amp;password=W1nter2024&amp;sslmode=require"},
		{"kingfisher.jdbc.3", `datasource.url: "jdbc:sqlserver://sqlserver.test;user=fixture_user;password=fixture_pw_012345;"`},
		{"kingfisher.jdbc.4", "url=jdbc:oracle:thin:svc_report/Xk4_Vt9qLp22@//db01.corp.internal:1533/RPTD"},
		{"kingfisher.jdbc.4", "jdbc:oracle:thin:APPTEST1/s3cretPw@10.0.0.57:1521:dev81"},
		{"kingfisher.discord.2", `client.login("MTA5NTYxMjM0NTY3ODkwMTIz.GhJkLm.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab")`},
		{"kingfisher.plaid.1", "Plaid API credentials. client_id = 5f0c1b2d3e4f5a6b7c8d9e0f and plaid_api_secret = ..."},
	}
	for _, c := range cases {
		t.Run(c.rule+"/"+c.input, func(t *testing.T) {
			_, pipeline := ruleOutcome(t, loadBuiltinRule(t, c.rule), c.input)
			assert.Positivef(t, pipeline, "%q was not detected", c.input)
		})
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
