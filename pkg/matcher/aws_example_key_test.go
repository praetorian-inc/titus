// LAB-6509: AWS documentation placeholder key IDs (last 7 characters "EXAMPLE")
// must not be reported as credentials, while real keys -- and near-misses that
// only *look* like placeholders -- must still be.
//
// Both np.aws.1 and np.aws.6 share a key-ID sub-pattern that gained a negative
// lookahead, `(?![A-Z0-9]{9}EXAMPLE\b)`, so the regex itself now declines the
// placeholders.
//
// Every case here asserts BOTH pipeline stages, and that is load-bearing rather
// than incidental. np.aws.1 already carried
// `pattern_requirements.ignore_if_contains: ["EXAMPLE"]` before the lookahead
// existed, so its placeholders were already dropped by the post-filter -- a
// post-filter-only assertion would pass against the broken pattern and prove
// nothing about the lookahead. The regex-stage count is what actually pins the
// pattern. np.aws.6 has no pattern_requirements at all, so for that rule the
// regex is the only thing standing between a documentation snippet and a
// reported credential, and both counts move together.
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

// awsExampleRuleIDs are the two rules LAB-6509 taught to reject AWS
// documentation placeholder key IDs.
var awsExampleRuleIDs = []string{"np.aws.1", "np.aws.6"}

// awsDocPlaceholderKeyIDs holds five key-ID prefixes covering the shapes the
// lookahead must reject. It is deliberately NOT an exhaustive list of the
// alternation, and not all five come from AWS.
//
// Four (AKIA, ASIA, AIDA, AROA) appear as placeholders in AWS's published
// documentation. The fifth, A3T0, is constructed: AWS publishes no A3T
// placeholder. It is here because `A3T[A-Z0-9]` is the only branch of the
// alternation that consumes a character class rather than a literal, so it is
// the one whose interaction with the following `(?![A-Z0-9]{9}EXAMPLE\b)` is
// worth pinning explicitly.
//
// Of the alternation's nine branches, the remaining four (AGPA, AIPA, ANPA,
// ANVA) are not represented. They need no case of their own: the lookahead
// sits AFTER the shared prefix alternation, so it is prefix-agnostic by
// construction. Multiple prefixes are covered here only so that a fix wrongly
// written per-prefix -- one that handled AKIA alone -- fails loudly rather
// than silently leaving the others reporting.
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

// loadAWSRule returns one built-in rule by ID.
func loadAWSRule(t *testing.T, id string) *types.Rule {
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

// awsOutcome runs the FULL pipeline for one rule against one input: the regex
// stage, then the filterMatches post-filters. It reports the surviving count at
// each stage separately so a test can say which stage did (or failed to do) the
// rejecting. Mirrors exampleOutcome in rule_examples_test.go.
func awsOutcome(t *testing.T, r *types.Rule, input string) (regexMatches, pipelineMatches int) {
	t.Helper()
	// 5s rather than the 500ms production default, for the same reason
	// exampleOutcome uses it: the question is whether the rule CAN match, not
	// whether it does so quickly on a loaded CI runner.
	m, err := NewPortableRegexpWithTimeout([]*types.Rule{r}, 0, nil, 5*time.Second)
	require.NoErrorf(t, err, "rule %q: building matcher", r.ID)

	ms, err := m.Match([]byte(input))
	require.NoErrorf(t, err, "rule %q: matching input %q", r.ID, input)

	regexMatches = len(ms)
	pipelineMatches = len(filterMatches(ms, map[string]*types.Rule{r.ID: r}))
	return regexMatches, pipelineMatches
}

// awsInputFor wraps a bare key ID into an input shaped for the given rule.
//
// np.aws.1 matches a lone key ID. np.aws.6 requires a key ID AND a 40-char
// secret within 40 characters of it, so a bare key ID would produce zero
// matches for reasons that have nothing to do with the lookahead -- and every
// "must not match" assertion would pass vacuously. Hence the pair.
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
		r := loadAWSRule(t, ruleID)
		for _, keyID := range awsDocPlaceholderKeyIDs {
			t.Run(ruleID+"/"+keyID, func(t *testing.T) {
				input := awsInputFor(ruleID, keyID, awsDocPlaceholderSecret)
				rx, pipeline := awsOutcome(t, r, input)

				assert.Zerof(t, rx, "rule %q: pattern matched AWS documentation placeholder key ID %q "+
					"(input %q) -- the EXAMPLE negative lookahead is missing or too narrow", ruleID, keyID, input)
				assert.Zerof(t, pipeline, "rule %q: AWS documentation placeholder key ID %q survived the full "+
					"pipeline (input %q) and would be reported as a credential", ruleID, keyID, input)
			})
		}
	}
}

// awsIgnoreIfContainsSubstringDrop is the reason np.aws.1 drops a key ID whose
// body contains "EXAMPLE" away from the final 7 characters.
//
// np.aws.1 carries pattern_requirements.ignore_if_contains: ["EXAMPLE"], which
// predates this branch (present at merge-base e5faeee). passesPatternRequirements
// (postfilter.go:75-86) applies it as a plain case-insensitive SUBSTRING test on
// the selected capture, and for np.aws.1 that capture is key_id itself -- so
// position is irrelevant at the post-filter, and the LOOKAHEAD's correct verdict
// is not what decides the outcome there.
//
// Whether that filter should be narrowed now that the precise lookahead exists is
// out of scope for LAB-6509 and is with the reviewer. This constant records the
// mechanism, not a verdict on it.
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
		// drop this key ID even though its pattern admits it. Keyed by rule ID so
		// the ID lives in exactly one place, and carrying the reason as data so the
		// failure message can quote the specific one -- the shape of
		// knownExampleFailures in rule_examples_test.go, the convention this repo
		// already uses for pinning behavior that a stage other than the one under
		// test governs.
		//
		// Absent for every rule that reports the key ID normally: np.aws.6 has no
		// pattern_requirements at all, so it never appears here.
		pipelineDropsFor map[string]string
	}{
		{name: "real_AKIA", keyID: "AKIADEADBEEFDEADBEEF", why: "ordinary AKIA key, nothing EXAMPLE-like about it"},
		{name: "real_A3T0", keyID: "A3T0ABCDEFGHIJKLMNOP", why: "ordinary A3T-family key"},
		{name: "nearmiss_trailing_Z", keyID: "AKIAIOSFODNN7EXAMPLZ", why: "last 7 chars are EXAMPLZ, not EXAMPLE"},
		{name: "nearmiss_trailing_0", keyID: "AKIAIOSFODNN7EXAMPL0", why: "last 7 chars are EXAMPL0, not EXAMPLE"},
		// The two trailing_* cases above vary the LAST character, so they only prove
		// the lookahead is not keying off a loose "EXAMPLE" substring. They do not
		// prove it is positionally anchored to the end of the 16-char body: a
		// mis-written `(?!.*EXAMPLE)` or `(?![A-Z0-9]*EXAMPLE)` passes both of them
		// while wrongly suppressing real keys that merely contain EXAMPLE earlier.
		// These two are that proof.
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
		r := loadAWSRule(t, ruleID)
		for _, tc := range cases {
			t.Run(ruleID+"/"+tc.name, func(t *testing.T) {
				input := awsInputFor(ruleID, tc.keyID, awsRealSecret)
				rx, pipeline := awsOutcome(t, r, input)

				// The regex-stage assertion is unconditional: it is what proves the
				// lookahead is positionally anchored to the last 7 characters, and it
				// holds for every rule and every case here.
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

// Drive each rule's own negative_examples through the pipeline.
//
// The repo loads rule.NegativeExamples (pkg/rule/loader.go) but has no global
// test asserting they fail to match, so without this the YAML entries are inert
// documentation. Asserted at the pipeline stage only: negative_examples promise
// "produces no finding", and some of them (e.g. lowercase key IDs) were never
// regex matches to begin with.
func TestAWSExampleKeys_NegativeExamplesProduceNoFindings(t *testing.T) {
	for _, ruleID := range awsExampleRuleIDs {
		r := loadAWSRule(t, ruleID)
		require.NotEmptyf(t, r.NegativeExamples, "rule %q declares no negative_examples -- "+
			"this test has nothing to guard", ruleID)

		for i, ex := range r.NegativeExamples {
			t.Run(fmt.Sprintf("%s/negative_example_%d", ruleID, i), func(t *testing.T) {
				_, pipeline := awsOutcome(t, r, ex)
				assert.Zerof(t, pipeline, "rule %q: negative_examples[%d] produced %d surviving match(es) "+
					"but must produce none.\ninput: %q", ruleID, i, pipeline, ex)
			})
		}
	}
}
