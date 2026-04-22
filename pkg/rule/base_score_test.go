package rule

import (
	"strings"
	"testing"
)

// TestAllRules_HaveBaseScore verifies every embedded rule has base_score > 0.
// A base_score of 0 is technically "info tier" but is also the Go zero value,
// so we use it as a sentinel for "researcher forgot to score this rule".
func TestAllRules_HaveBaseScore(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		t.Fatalf("LoadBuiltinRules: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules loaded")
	}

	var missing []string
	for _, r := range rules {
		if r.BaseScore <= 0 {
			missing = append(missing, r.ID)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d rules have base_score <= 0:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// TestCriticalTier_RulesExist ensures we have at least some critical-tier rules,
// catching accidental mass downgrades.
func TestCriticalTier_RulesExist(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		t.Fatal(err)
	}
	critical := 0
	for _, r := range rules {
		if r.BaseScore >= 80 {
			critical++
		}
	}
	if critical == 0 {
		t.Error("no rules in critical tier (base_score >= 80) — verify tier assignments")
	}
	t.Logf("Critical tier: %d rules", critical)
}

// TestTierBoundaries catches obvious mis-tiering by checking rule names against
// expected tier floors. A rule named "aws.*" or containing "private_key" should
// be at least tier "high" (60+).
func TestTierBoundaries(t *testing.T) {
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		t.Fatal(err)
	}

	type requirement struct {
		idContains string
		minScore   int
		reason     string
	}
	// Use specific rule ID substrings that unambiguously identify secret-bearing rules.
	// Broad prefixes (e.g. "np.aws.") are intentionally avoided because some AWS rules
	// detect public identifiers (account IDs, ARNs) and legitimately have lower scores.
	requirements := []requirement{
		{idContains: "np.aws.2", minScore: 60, reason: "AWS Secret Access Key is a high-tier credential"},
		{idContains: "np.aws.6", minScore: 60, reason: "AWS API Credentials are high-tier"},
		{idContains: "np.pem.", minScore: 80, reason: "PEM private keys are critical-tier"},
		{idContains: "np.stripe.1", minScore: 80, reason: "Stripe live API keys move money"},
	}

	var violations []string
	for _, r := range rules {
		for _, req := range requirements {
			if strings.Contains(r.ID, req.idContains) && r.BaseScore < req.minScore {
				violations = append(violations,
					r.ID+": base_score="+
						itoa(r.BaseScore)+
						" below required "+
						itoa(req.minScore)+
						" ("+req.reason+")")
			}
		}
	}
	if len(violations) > 0 {
		t.Errorf("tier boundary violations:\n  %s", strings.Join(violations, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
