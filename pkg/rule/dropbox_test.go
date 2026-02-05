package rule

import (
	"strings"
	"testing"
)

// TestDropboxRule_HasNamedCaptureGroup verifies the np.dropbox.1 rule
// has a named capture group called "token" required for validation
func TestDropboxRule_HasNamedCaptureGroup(t *testing.T) {
	// Load the dropbox rule
	loader := NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		t.Fatalf("failed to load builtin rules: %v", err)
	}

	// Find the dropbox rule
	var dropboxPattern string
	for _, rule := range rules {
		if rule.ID == "np.dropbox.1" {
			dropboxPattern = rule.Pattern
			break
		}
	}

	if dropboxPattern == "" {
		t.Fatal("dropbox rule not found - np.dropbox.1 rule ID not found in builtin rules")
	}

	// Test that the pattern has a named capture group called "token"
	// This is required for the validator to extract the secret
	if !strings.Contains(dropboxPattern, "(?P<token>") {
		t.Errorf("dropbox rule pattern must have named capture group '(?P<token>' for validator integration, got pattern: %s", dropboxPattern)
	}
}
