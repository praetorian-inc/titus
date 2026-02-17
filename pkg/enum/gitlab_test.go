package enum

import (
	"context"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestGitLabEnumerator_RequiresToken(t *testing.T) {
	// Test that GitLabEnumerator requires a token
	_, err := NewGitLabEnumerator(GitLabConfig{
		Token: "",
		Project: "owner/project",
		Config: Config{
			MaxFileSize: 10 * 1024 * 1024,
		},
	})

	if err == nil {
		t.Error("expected error when token is empty, got nil")
	}
}

func TestGitLabEnumerator_RequiresProjectOrGroupOrUser(t *testing.T) {
	// Test that at least one of Project, Group, or User must be specified
	_, err := NewGitLabEnumerator(GitLabConfig{
		Token: "glpat_test",
		Config: Config{
			MaxFileSize: 10 * 1024 * 1024,
		},
	})

	if err == nil {
		t.Error("expected error when no project/group/user specified, got nil")
	}
}

func TestGitLabEnumerator_ValidConfig(t *testing.T) {
	// Test that valid config creates enumerator
	tests := []struct {
		name   string
		config GitLabConfig
	}{
		{
			name: "with project",
			config: GitLabConfig{
				Token:   "glpat_test",
				Project: "owner/project",
				Config: Config{
					MaxFileSize: 10 * 1024 * 1024,
				},
			},
		},
		{
			name: "with group",
			config: GitLabConfig{
				Token: "glpat_test",
				Group: "mygroup",
				Config: Config{
					MaxFileSize: 10 * 1024 * 1024,
				},
			},
		},
		{
			name: "with user",
			config: GitLabConfig{
				Token: "glpat_test",
				User:  "username",
				Config: Config{
					MaxFileSize: 10 * 1024 * 1024,
				},
			},
		},
		{
			name: "with custom URL",
			config: GitLabConfig{
				Token:   "glpat_test",
				Project: "owner/project",
				BaseURL: "https://gitlab.company.com",
				Config: Config{
					MaxFileSize: 10 * 1024 * 1024,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enumerator, err := NewGitLabEnumerator(tt.config)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if enumerator == nil {
				t.Error("expected enumerator, got nil")
			}
		})
	}
}

// Note: The following tests would require mocking the GitLab API client
// In a real implementation, we would use a mock client or integration tests
// against a test GitLab instance. For now, we're testing the structure.

func TestGitLabEnumerator_Interface(t *testing.T) {
	// Verify GitLabEnumerator implements Enumerator interface
	var _ Enumerator = (*GitLabEnumerator)(nil)
}

func TestGitLabEnumerator_BlobID(t *testing.T) {
	// This test would verify that blob IDs are computed correctly
	// In a real scenario, we'd mock the GitLab API response
	// For now, we verify the structure exists
	config := GitLabConfig{
		Token:   "glpat_test",
		Project: "owner/project",
		Config: Config{
			MaxFileSize: 10 * 1024 * 1024,
		},
	}

	enumerator, err := NewGitLabEnumerator(config)
	if err != nil {
		t.Fatalf("failed to create enumerator: %v", err)
	}

	// In a real test, we would:
	// 1. Mock GitLab API to return test files
	// 2. Call Enumerate
	// 3. Verify blob IDs are computed correctly
	// 4. Verify provenance is GitProvenance
	_ = enumerator
}

func TestGitLabConfig_Structure(t *testing.T) {
	// Verify GitLabConfig has expected fields
	config := GitLabConfig{
		Token:   "test-token",
		BaseURL: "https://gitlab.com",
		Project: "owner/project",
		Group:   "mygroup",
		User:    "username",
		Config: Config{
			MaxFileSize: 1000,
		},
	}

	if config.Token != "test-token" {
		t.Error("Token field not accessible")
	}
	if config.BaseURL != "https://gitlab.com" {
		t.Error("BaseURL field not accessible")
	}
	if config.Project != "owner/project" {
		t.Error("Project field not accessible")
	}
	if config.Group != "mygroup" {
		t.Error("Group field not accessible")
	}
	if config.User != "username" {
		t.Error("User field not accessible")
	}
	if config.Config.MaxFileSize != 1000 {
		t.Error("Config.MaxFileSize not accessible")
	}
}

func TestGitLabEnumerator_Callback(t *testing.T) {
	// Verify that Enumerate method signature matches interface
	config := GitLabConfig{
		Token:   "glpat_test",
		Project: "owner/project",
		Config: Config{
			MaxFileSize: 10 * 1024 * 1024,
		},
	}

	enumerator, err := NewGitLabEnumerator(config)
	if err != nil {
		t.Fatalf("failed to create enumerator: %v", err)
	}

	// Verify callback signature matches
	callback := func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		return nil
	}

	// In a real test with mocked API, this would call the callback
	// For now, we just verify the method exists and signature is correct
	ctx := context.Background()
	_ = enumerator.Enumerate(ctx, callback)

	// With a real GitLab API mock, the callback would be called
	// For structure verification, we just ensure no panic
}
