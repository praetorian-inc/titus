package matcher

import (
	"testing"
	"time"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- SecretCapture tests ---

func TestSecretCapture_SecretGroupWins(t *testing.T) {
	m := &types.Match{NamedGroups: map[string][]byte{
		"host":     []byte("pgdb01-rds.prod.internal"), // higher entropy than the password
		"password": []byte("hunter2"),
		"token":    []byte("not-the-secret-either"),
	}}
	assert.Equal(t, "hunter2", string(SecretCapture(m, "password")), "secret_group beats both entropy and the token convention")
}

func TestSecretCapture_TokenNamed(t *testing.T) {
	m := &types.Match{NamedGroups: map[string][]byte{"TOKEN": []byte("secret123"), "other": []byte("noise")}}
	assert.Equal(t, "secret123", string(SecretCapture(m, "")))
	m = &types.Match{NamedGroups: map[string][]byte{"token": []byte("lowtoken")}}
	assert.Equal(t, "lowtoken", string(SecretCapture(m, "")), "token match is case-insensitive")
}

func TestSecretCapture_SoleNamedGroup(t *testing.T) {
	m := &types.Match{NamedGroups: map[string][]byte{"key": []byte("keyvalue")}}
	assert.Equal(t, "keyvalue", string(SecretCapture(m, "")))
}

func TestSecretCapture_UnknownSecretGroupFallsThrough(t *testing.T) {
	m := &types.Match{NamedGroups: map[string][]byte{"key": []byte("keyvalue")}}
	assert.Equal(t, "keyvalue", string(SecretCapture(m, "missing")), "a secret_group absent from this match must not blank the secret")
}

// Several named groups and no secret_group cannot happen for loaded rules
// (the loader rejects it); if reached, selection falls to positional captures
// rather than guessing between the names.
func TestSecretCapture_MultipleNamedWithoutSecretGroupUsesPositional(t *testing.T) {
	m := &types.Match{
		NamedGroups: map[string][]byte{"host": []byte("db"), "password": []byte("pw")},
		Groups:      [][]byte{[]byte("db"), []byte("pw")},
	}
	assert.Equal(t, "pw", string(SecretCapture(m, "")))
}

func TestSecretCapture_Positional(t *testing.T) {
	assert.Equal(t, "capture1", string(SecretCapture(&types.Match{Groups: [][]byte{[]byte("full"), []byte("capture1")}}, "")))
	assert.Equal(t, "fullmatch", string(SecretCapture(&types.Match{Groups: [][]byte{[]byte("fullmatch")}}, "")))
	assert.Nil(t, SecretCapture(&types.Match{}, ""))
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

func TestPassesPatternRequirements_Luhn(t *testing.T) {
	reqs := &types.PatternRequirements{Luhn: true}
	assert.True(t, passesPatternRequirements([]byte("4532015112830366"), reqs))
	assert.True(t, passesPatternRequirements([]byte("4532-0151-1283-0366"), reqs))
	assert.True(t, passesPatternRequirements([]byte("4532 0151 1283 0366"), reqs))
	assert.True(t, passesPatternRequirements([]byte("378282246310005"), reqs), "15-digit amex")
	assert.False(t, passesPatternRequirements([]byte("4532015112830367"), reqs), "check digit off by one")
	assert.False(t, passesPatternRequirements([]byte("1234567890123456"), reqs))
	assert.False(t, passesPatternRequirements([]byte("4532O15112830366"), reqs), "letter O is not a digit")
	assert.False(t, passesPatternRequirements([]byte("4532015112"), reqs), "too short")
	assert.False(t, passesPatternRequirements([]byte("45320151128303664532"), reqs), "too long")
	assert.True(t, passesPatternRequirements([]byte("not-a-number"), &types.PatternRequirements{}), "luhn off")
}

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

// A multi-group match passes min_entropy on the declared secret group even
// when its other groups (db="0") would fail on their own.
func TestPassesEntropyCheck_WithMultiGroupMatch(t *testing.T) {
	password := []byte("oJs3RjFV5CVDyObDiooJk8NGGSylGTlNmAzCaPVydjM=")
	m := &types.Match{NamedGroups: map[string][]byte{"db": []byte("0"), "password": password}}
	assert.True(t, passesEntropyCheck(SecretCapture(m, "password"), 3.0))
	assert.False(t, passesEntropyCheck([]byte("0"), 3.0), "sanity: db alone fails")
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

// TestFindSecretCapture_MultiCaptureRulesSelectPassword verifies that rules
// with 3+ captures select the password (via the named "token" group), not a
// middle field like the login or username.
//
// Before LAB-6101, these rules had no named groups, so SecretCapture fell
// through to Groups[1] — the second capture — which was a username or path.
// Entropy and pattern_requirements checks ran against that field instead of
// the actual credential.
func TestSecretCapture_MultiCaptureRulesSelectPassword(t *testing.T) {
	allRules, err := rule.NewLoader().LoadBuiltinRules()
	require.NoError(t, err)

	byID := map[string]*types.Rule{}
	for _, r := range allRules {
		byID[r.ID] = r
	}

	tests := []struct {
		ruleID   string
		input    string
		wantSecret string
	}{
		{
			ruleID:     "np.netrc.1",
			input:      "machine api.github.com login ziggy^stardust password 012345abcdef",
			wantSecret: "012345abcdef",
		},
		{
			ruleID:     "np.phpmailer.1",
			input:      "$mail->Host = 'smtp.example.com';\n$mail->Username = 'user@example.com';\n$mail->Password = 'un!techwhooah';",
			wantSecret: "un!techwhooah",
		},
		{
			ruleID:     "np.generic.8",
			input:      `$domain = New-Object DirectoryServices.DirectoryEntry("LDAP://10.10.10.1","domain\user", "secret")`,
			wantSecret: "secret",
		},
		// Before secret_group these four were decided by max entropy, which
		// picked the hostname (or the AWS key ID) over the credential.
		{
			ruleID:     "np.postgres.1",
			input:      "DATABASE_URL=postgresql://app_user:Tr0ub4dor@pgdb01-rds.prod.internal:5432/billing",
			wantSecret: "Tr0ub4dor",
		},
		{
			ruleID:     "kingfisher.rabbitmq.1",
			input:      "amqp://svc_orders:Qz7vLm2pKe@mq-primary.prod.internal:5672/orders",
			wantSecret: "Qz7vLm2pKe",
		},
		{
			ruleID:     "np.mongodb.1",
			input:      "mongodb://reporting:Xk4_Vt9qLp22@mongo-rs0.analytics.internal:27017/warehouse",
			wantSecret: "Xk4_Vt9qLp22",
		},
		{
			// Assembled at runtime so the synthetic pair is not a literal in the repo.
			ruleID:     "np.aws.6",
			input:      "AWS_ACCESS_KEY_ID=AKIA4RQ6ZGKJ" + "7XMP2TL3\nAWS_SECRET_ACCESS_KEY=" + "9vK2xQp1Rb8sT4uWy6zA" + "3cE5gH7jL0mN2oP4qS6t",
			wantSecret: "9vK2xQp1Rb8sT4uWy6zA" + "3cE5gH7jL0mN2oP4qS6t",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			r, ok := byID[tt.ruleID]
			require.True(t, ok, "rule %s not found", tt.ruleID)

			m, err := NewPortableRegexpWithTimeout([]*types.Rule{r}, 0, nil, 5*time.Second)
			require.NoError(t, err)

			matches, err := m.Match([]byte(tt.input))
			require.NoError(t, err)
			require.NotEmpty(t, matches, "rule %s did not match its input", tt.ruleID)

			secret := SecretCapture(matches[0], r.SecretGroup)
			assert.Equal(t, tt.wantSecret, string(secret),
				"SecretCapture should select the password, not another capture")
		})
	}
}
