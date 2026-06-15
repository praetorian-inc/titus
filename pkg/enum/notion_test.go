package enum

import (
	"testing"
)

// TestNotionEnumerator_Construction tests that we can create a Notion enumerator.
func TestNotionEnumerator_Construction(t *testing.T) {
	config := NotionConfig{
		Token: "test-token",
	}

	enumerator, err := NewNotionEnumerator(config)
	if err != nil {
		t.Fatalf("failed to create Notion enumerator: %v", err)
	}

	if enumerator == nil {
		t.Fatal("enumerator is nil")
	}
}

// TestNotionEnumerator_Interface verifies NotionEnumerator implements Enumerator.
func TestNotionEnumerator_Interface(t *testing.T) {
	config := NotionConfig{
		Token: "test-token",
	}

	enumerator, err := NewNotionEnumerator(config)
	if err != nil {
		t.Fatalf("failed to create Notion enumerator: %v", err)
	}

	// Verify it implements Enumerator interface
	var _ Enumerator = enumerator
}

// TestNotionEnumerator_RequiresToken tests that an empty token produces an error.
func TestNotionEnumerator_RequiresToken(t *testing.T) {
	config := NotionConfig{
		Token: "",
	}

	enumerator, err := NewNotionEnumerator(config)
	if err == nil {
		t.Fatal("expected error when token is empty, got nil")
	}
	if enumerator != nil {
		t.Fatal("expected nil enumerator when token is empty")
	}
}

// TestNotionEnumerator_DefaultConcurrency tests that Concurrency defaults to 3.
func TestNotionEnumerator_DefaultConcurrency(t *testing.T) {
	config := NotionConfig{
		Token:       "test-token",
		Concurrency: 0,
	}

	enumerator, err := NewNotionEnumerator(config)
	if err != nil {
		t.Fatalf("failed to create Notion enumerator: %v", err)
	}

	if enumerator.config.Concurrency != 3 {
		t.Fatalf("expected default concurrency 3, got %d", enumerator.config.Concurrency)
	}
}

// TestNotionEnumerator_DefaultRateLimit tests that RateLimit defaults to 3.0.
func TestNotionEnumerator_DefaultRateLimit(t *testing.T) {
	config := NotionConfig{
		Token:     "test-token",
		RateLimit: 0,
	}

	enumerator, err := NewNotionEnumerator(config)
	if err != nil {
		t.Fatalf("failed to create Notion enumerator: %v", err)
	}

	if enumerator.config.RateLimit != 3.0 {
		t.Fatalf("expected default rate limit 3.0, got %f", enumerator.config.RateLimit)
	}
}

// TestNotionEnumerator_CustomConcurrency tests that a custom Concurrency value is preserved.
func TestNotionEnumerator_CustomConcurrency(t *testing.T) {
	config := NotionConfig{
		Token:       "test-token",
		Concurrency: 10,
	}

	enumerator, err := NewNotionEnumerator(config)
	if err != nil {
		t.Fatalf("failed to create Notion enumerator: %v", err)
	}

	if enumerator.config.Concurrency != 10 {
		t.Fatalf("expected concurrency 10, got %d", enumerator.config.Concurrency)
	}
}

// TestNotionProvenance tests that notionProvenance builds the correct ExtendedProvenance.
func TestNotionProvenance(t *testing.T) {
	prov := notionProvenance("page-id", "Test Page", "https://notion.so/pageid", "My Space")

	payload := prov.Payload
	if payload == nil {
		t.Fatal("expected non-nil payload")
	}
	if payload["source"] != "notion" {
		t.Fatalf("expected source 'notion', got %v", payload["source"])
	}
	if payload["pageID"] != "page-id" {
		t.Fatalf("expected pageID 'page-id', got %v", payload["pageID"])
	}
	if payload["title"] != "Test Page" {
		t.Fatalf("expected title 'Test Page', got %v", payload["title"])
	}
	if payload["url"] != "https://notion.so/pageid" {
		t.Fatalf("expected url 'https://notion.so/pageid', got %v", payload["url"])
	}
	if payload["space"] != "My Space" {
		t.Fatalf("expected space 'My Space', got %v", payload["space"])
	}
}

// TestNotionBlockText tests the nBlockText helper with various block types.
func TestNotionBlockText(t *testing.T) {
	tests := []struct {
		name     string
		bv       map[string]interface{}
		expected string
	}{
		{
			name: "text block extracts title",
			bv: map[string]interface{}{
				"type": "text",
				"properties": map[string]interface{}{
					"title": []interface{}{
						[]interface{}{"hello"},
					},
				},
			},
			expected: "hello",
		},
		{
			name: "header block extracts title",
			bv: map[string]interface{}{
				"type": "header",
				"properties": map[string]interface{}{
					"title": []interface{}{
						[]interface{}{"heading"},
					},
				},
			},
			expected: "heading",
		},
		{
			name: "divider block returns empty string",
			bv: map[string]interface{}{
				"type": "divider",
			},
			expected: "",
		},
		{
			name: "bulleted_list block extracts title",
			bv: map[string]interface{}{
				"type": "bulleted_list",
				"properties": map[string]interface{}{
					"title": []interface{}{
						[]interface{}{"item"},
					},
				},
			},
			expected: "item",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nBlockText(tt.bv)
			if got != tt.expected {
				t.Fatalf("nBlockText() = %q, want %q", got, tt.expected)
			}
		})
	}
}
