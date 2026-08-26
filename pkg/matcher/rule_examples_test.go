//go:build !race

// This guard is excluded from -race builds on purpose.
//
// It measures rule semantics -- can a rule detect the example it documents --
// and contains no concurrency, so the race detector has nothing to find here.
// What it does do is slow execution by roughly an order of magnitude, which
// pushes patterns that nest quantifiers over .* past any sane match timeout.
// np.phpmailer.1 exceeds even 30s under -race while passing comfortably in a
// normal run. Left in, this guard would fail the Race Detector job for reasons
// unrelated to correctness.
//
// np.phpmailer.1's backtracking cost deserves attention in its own right; it is
// not something this test should paper over, nor be blocked by.

package matcher

import (
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/require"
)

// knownExampleFailures lists rules that cannot currently detect their own
// documented examples. Tracked as LAB-6096.
//
// Entries are rule IDs, deliberately not a count: a count would let a fixed
// rule be silently traded for a newly broken one.
//
// TO FIX A RULE, DELETE ITS LINE HERE. TestRuleExamples_KnownFailuresStillFail
// fails if a listed rule starts passing, so the list can only shrink and a
// fixed rule cannot quietly stop being guarded.
//
// Each failure is one of two things, and they need opposite fixes:
//   - the example does not represent a real credential -> fix the example
//   - the rule's constraints exclude the real credential format -> fix the
//     rule, and treat it as a live detection gap
//
// Do NOT bulk-relax pattern_requirements to clear these. Those constraints
// exist to suppress false positives; loosening them blindly trades a
// false-negative problem for a false-positive one.
var knownExampleFailures = map[string]string{
	"kingfisher.airtable.2":     "1/1 examples fail at regex stage",
	"kingfisher.contentful.1":   "1/3 examples fail at regex stage",
	"kingfisher.contentful.2":   "1/4 examples fail at regex stage",
	"kingfisher.curl.2":         "1/3 examples fail at regex stage",
	"np.amplitude.1":            "1/2 examples fail at regex stage",
	"np.cypress.1":              "1/3 examples fail at regex stage",
	"np.redis.1":                "1/4 examples fail at regex stage",
	"np.twitter.3":              "1/3 examples fail at regex stage",
	"kingfisher.ai21studio.1":   "3/3 examples fail at postfilter stage",
	"kingfisher.anypoint.1":     "1/1 examples fail at postfilter stage",
	"kingfisher.asana.1":        "2/2 examples fail at postfilter stage",
	"kingfisher.asana.2":        "1/2 examples fail at postfilter stage",
	"kingfisher.azure.devops.1": "1/2 examples fail at postfilter stage",
	"kingfisher.beamer.1":       "2/2 examples fail at postfilter stage",
	"kingfisher.ciscomeraki.1":  "1/2 examples fail at postfilter stage",
	"kingfisher.clojars.1":      "1/1 examples fail at postfilter stage",
	"kingfisher.cloudflare.1":   "2/2 examples fail at postfilter stage",
	"kingfisher.cloudflare.2":   "2/2 examples fail at postfilter stage",
	"kingfisher.cloudsight.1":   "1/2 examples fail at postfilter stage",
	"kingfisher.discord.3":      "2/2 examples fail at postfilter stage",
	"kingfisher.filezilla.2":    "1/2 examples fail at postfilter stage",
	"kingfisher.freshbooks.1":   "1/2 examples fail at postfilter stage",
	"kingfisher.gocardless.1":   "1/2 examples fail at postfilter stage",
	"kingfisher.imagekit.1":     "1/2 examples fail at postfilter stage",
	"kingfisher.infracost.1":    "1/2 examples fail at postfilter stage",
	"kingfisher.ipstack.1":      "1/2 examples fail at postfilter stage",
	"kingfisher.jdbc.1":         "3/4 examples fail at postfilter stage",
	"kingfisher.jira.1":         "2/2 examples fail at postfilter stage",
	"kingfisher.lob.1":          "1/2 examples fail at postfilter stage",
	"kingfisher.lob.2":          "1/2 examples fail at postfilter stage",
	"kingfisher.mattermost.2":   "1/3 examples fail at postfilter stage",
	"kingfisher.messagebird.1":  "1/2 examples fail at postfilter stage",
	"kingfisher.mongodb.1":      "1/1 examples fail at postfilter stage",
	"kingfisher.mongodb.2":      "1/1 examples fail at postfilter stage",
	"kingfisher.mysql.1":        "1/2 examples fail at postfilter stage",
	"kingfisher.openweather.1":  "2/4 examples fail at postfilter stage",
	"kingfisher.planetscale.2":  "2/2 examples fail at postfilter stage",
	"kingfisher.prefect.1":      "1/2 examples fail at postfilter stage",
	"kingfisher.privkey.1":      "1/1 examples fail at postfilter stage",
	"kingfisher.privkey.2":      "1/5 examples fail at postfilter stage",
	"kingfisher.rabbitmq.1":     "2/4 examples fail at postfilter stage",
	"kingfisher.recaptcha.1":    "3/3 examples fail at postfilter stage",
	"kingfisher.runway.1":       "4/4 examples fail at postfilter stage",
	"kingfisher.scalingo.1":     "1/2 examples fail at postfilter stage",
	"kingfisher.scraperapi.1":   "1/2 examples fail at postfilter stage",
	"kingfisher.sendbird.2":     "1/1 examples fail at postfilter stage",
	"kingfisher.sentry.1":       "1/2 examples fail at postfilter stage",
	"kingfisher.sentry.3":       "1/2 examples fail at postfilter stage",
	"kingfisher.shippo.1":       "1/2 examples fail at postfilter stage",
	"kingfisher.supabase.2":     "1/2 examples fail at postfilter stage",
	"kingfisher.vercel.1":       "3/4 examples fail at postfilter stage",
}

// exampleOutcome reports how many of a rule's examples survive the full
// pipeline, and how many are lost at each stage.
func exampleOutcome(t *testing.T, r *types.Rule) (lostToRegex, lostToFilter int) {
	t.Helper()
	// 5s rather than the 500ms production default. The question here is whether
	// a rule CAN detect its example, not whether it does so quickly on a loaded
	// CI runner — a guard that passes on fast machines and fails on slow ones is
	// worse than no guard. 5s is the matcher's own fallback timeout, so it is a
	// generous ceiling rather than an arbitrary one.
	m, err := NewPortableRegexpWithTimeout([]*types.Rule{r}, 0, nil, 5*time.Second)
	if err != nil {
		return len(r.Examples), 0
	}
	for _, ex := range r.Examples {
		ms, err := m.Match([]byte(ex))
		if err != nil || len(ms) == 0 {
			lostToRegex++
			continue
		}
		if len(filterMatches(ms, map[string]*types.Rule{r.ID: r})) == 0 {
			lostToFilter++
		}
	}
	return lostToRegex, lostToFilter
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

// Every rule must detect the examples it documents.
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
		lostRegex, lostFilter := exampleOutcome(t, r)
		if lostRegex > 0 || lostFilter > 0 {
			t.Errorf("rule %q fails its own examples (%d unmatched by regex, %d dropped by post-filters).\n"+
				"Either the example is not a real credential, or the rule's pattern/requirements exclude it. "+
				"If this is a pre-existing failure being surfaced, add it to knownExampleFailures with a reason.",
				r.ID, lostRegex, lostFilter)
		}
	}
}

// A rule on the known-failures list that now passes must be removed from it.
//
// Without this the list rots: a rule gets fixed, its entry lingers, and that
// rule silently stops being guarded by the test above.
func TestRuleExamples_KnownFailuresStillFail(t *testing.T) {
	byID := map[string]*types.Rule{}
	for _, r := range rulesWithExamples(t) {
		byID[r.ID] = r
	}
	for id := range knownExampleFailures {
		r, ok := byID[id]
		if !ok {
			t.Errorf("knownExampleFailures lists %q, which no longer exists or has no examples — remove the entry", id)
			continue
		}
		lostRegex, lostFilter := exampleOutcome(t, r)
		if lostRegex == 0 && lostFilter == 0 {
			t.Errorf("rule %q now detects all its examples — delete its line from knownExampleFailures", id)
		}
	}
}
