package matcher

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// --- findSecretCapture tests ---

func TestFindSecretCapture_TokenNamed(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"TOKEN": []byte("secret123"),
			"other": []byte("noise"),
		},
	}
	got := findSecretCapture(m)
	if string(got) != "secret123" {
		t.Errorf("expected 'secret123', got %q", got)
	}
}

func TestFindSecretCapture_TokenCaseInsensitive(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"token": []byte("lowtoken"),
		},
	}
	got := findSecretCapture(m)
	if string(got) != "lowtoken" {
		t.Errorf("expected 'lowtoken', got %q", got)
	}
}

func TestFindSecretCapture_FirstNamedGroup(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{
			"key": []byte("keyvalue"),
		},
	}
	got := findSecretCapture(m)
	if string(got) != "keyvalue" {
		t.Errorf("expected 'keyvalue', got %q", got)
	}
}

func TestFindSecretCapture_Groups1(t *testing.T) {
	m := &types.Match{
		Groups: [][]byte{[]byte("full"), []byte("capture1")},
	}
	got := findSecretCapture(m)
	if string(got) != "capture1" {
		t.Errorf("expected 'capture1', got %q", got)
	}
}

func TestFindSecretCapture_Groups0Fallback(t *testing.T) {
	m := &types.Match{
		Groups: [][]byte{[]byte("fullmatch")},
	}
	got := findSecretCapture(m)
	if string(got) != "fullmatch" {
		t.Errorf("expected 'fullmatch', got %q", got)
	}
}

func TestFindSecretCapture_NoGroups(t *testing.T) {
	m := &types.Match{}
	got := findSecretCapture(m)
	if got != nil {
		t.Errorf("expected nil, got %q", got)
	}
}

// --- passesEntropyCheck tests ---

func TestPassesEntropyCheck_ZeroThreshold(t *testing.T) {
	// Zero threshold means no check — everything passes
	if !passesEntropyCheck([]byte("aaaa"), 0) {
		t.Error("expected pass for zero threshold")
	}
}

func TestPassesEntropyCheck_HighEntropyPasses(t *testing.T) {
	// High-entropy secret passes a low threshold
	secret := []byte("aB3$xY9!mN2@kL7#")
	if !passesEntropyCheck(secret, 2.0) {
		t.Error("expected high-entropy secret to pass threshold 2.0")
	}
}

func TestPassesEntropyCheck_LowEntropyRejected(t *testing.T) {
	// Repeated chars → entropy 0, should be rejected
	if passesEntropyCheck([]byte("aaaaaaa"), 1.0) {
		t.Error("expected low-entropy secret to be rejected")
	}
}

func TestPassesEntropyCheck_ExactEqualsRejects(t *testing.T) {
	// "ab" has entropy exactly 1.0 — <= 1.0 should reject
	if passesEntropyCheck([]byte("ab"), 1.0) {
		t.Error("expected entropy == threshold to be rejected")
	}
}

// --- passesPatternRequirements tests ---

func TestPassesPatternRequirements_Nil(t *testing.T) {
	if !passesPatternRequirements([]byte("anything"), nil) {
		t.Error("expected nil requirements to pass")
	}
}

func TestPassesPatternRequirements_MinDigits(t *testing.T) {
	reqs := &types.PatternRequirements{MinDigits: 3}
	if passesPatternRequirements([]byte("ab12"), reqs) {
		t.Error("expected fail: only 2 digits")
	}
	if !passesPatternRequirements([]byte("abc123"), reqs) {
		t.Error("expected pass: 3 digits")
	}
}

func TestPassesPatternRequirements_MinUppercase(t *testing.T) {
	reqs := &types.PatternRequirements{MinUppercase: 2}
	if passesPatternRequirements([]byte("Abcd"), reqs) {
		t.Error("expected fail: only 1 uppercase")
	}
	if !passesPatternRequirements([]byte("ABcd"), reqs) {
		t.Error("expected pass: 2 uppercase")
	}
}

func TestPassesPatternRequirements_MinLowercase(t *testing.T) {
	reqs := &types.PatternRequirements{MinLowercase: 3}
	if passesPatternRequirements([]byte("ABCd"), reqs) {
		t.Error("expected fail: only 1 lowercase")
	}
	if !passesPatternRequirements([]byte("ABCdef"), reqs) {
		t.Error("expected pass: 3 lowercase")
	}
}

func TestPassesPatternRequirements_IgnoreIfContains(t *testing.T) {
	reqs := &types.PatternRequirements{
		IgnoreIfContains: []string{"EXAMPLE", "test"},
	}
	// Case-insensitive: "example" should match "EXAMPLE"
	if passesPatternRequirements([]byte("sk_live_example_key"), reqs) {
		t.Error("expected fail: contains 'example'")
	}
	if passesPatternRequirements([]byte("sk_live_TEST_key"), reqs) {
		t.Error("expected fail: contains 'test' (case-insensitive)")
	}
	if !passesPatternRequirements([]byte("sk_live_realkey123"), reqs) {
		t.Error("expected pass: no ignored substrings")
	}
}

func TestPassesPatternRequirements_MinSpecialChars(t *testing.T) {
	reqs := &types.PatternRequirements{MinSpecialChars: 2}
	if passesPatternRequirements([]byte("abc!def"), reqs) {
		t.Error("expected fail: only 1 special char")
	}
	if !passesPatternRequirements([]byte("abc!def@"), reqs) {
		t.Error("expected pass: 2 special chars")
	}
}

func TestPassesPatternRequirements_CustomSpecialChars(t *testing.T) {
	reqs := &types.PatternRequirements{
		MinSpecialChars: 1,
		SpecialChars:    "-_",
	}
	if passesPatternRequirements([]byte("abc!def"), reqs) {
		t.Error("expected fail: '!' not in custom special chars")
	}
	if !passesPatternRequirements([]byte("abc_def"), reqs) {
		t.Error("expected pass: '_' is in custom special chars")
	}
}

// --- filterMatches tests ---

func TestFilterMatches_Empty(t *testing.T) {
	result := filterMatches(nil, map[string]*types.Rule{})
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestFilterMatches_PassesWhenNoRule(t *testing.T) {
	matches := []*types.Match{
		{RuleID: "unknown.rule", Groups: [][]byte{[]byte("val")}},
	}
	result := filterMatches(matches, map[string]*types.Rule{})
	if len(result) != 1 {
		t.Errorf("expected match to pass through when rule not found, got %d", len(result))
	}
}

func TestFilterMatches_EntropyFiltering(t *testing.T) {
	rules := map[string]*types.Rule{
		"np.test.1": {
			ID:         "np.test.1",
			MinEntropy: 3.0,
		},
	}
	matches := []*types.Match{
		{
			RuleID: "np.test.1",
			Groups: [][]byte{[]byte("full"), []byte("aaaaaaa")}, // low entropy
		},
		{
			RuleID: "np.test.1",
			Groups: [][]byte{[]byte("full"), []byte("aB3$xY9!mN2@kL7#pQ1z")}, // high entropy
		},
	}
	result := filterMatches(matches, rules)
	if len(result) != 1 {
		t.Errorf("expected 1 match after entropy filtering, got %d", len(result))
	}
}

func TestFilterMatches_PatternRequirementsFiltering(t *testing.T) {
	rules := map[string]*types.Rule{
		"np.test.2": {
			ID: "np.test.2",
			PatternRequirements: &types.PatternRequirements{
				IgnoreIfContains: []string{"example"},
			},
		},
	}
	matches := []*types.Match{
		{
			RuleID: "np.test.2",
			NamedGroups: map[string][]byte{
				"token": []byte("sk_live_EXAMPLE_key"),
			},
		},
		{
			RuleID: "np.test.2",
			NamedGroups: map[string][]byte{
				"token": []byte("sk_live_realkey12345"),
			},
		},
	}
	result := filterMatches(matches, rules)
	if len(result) != 1 {
		t.Errorf("expected 1 match after pattern requirements filtering, got %d", len(result))
	}
	if string(result[0].NamedGroups["token"]) != "sk_live_realkey12345" {
		t.Errorf("unexpected match content: %q", result[0].NamedGroups["token"])
	}
}
