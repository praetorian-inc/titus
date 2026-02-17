//go:build wasm

package main

import (
	"encoding/json"
	"syscall/js"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

// TestScannerCreation tests creating a scanner with builtin rules
func TestScannerCreation(t *testing.T) {
	// Create scanner with builtin rules
	result := newScanner(js.Value{}, []js.Value{js.ValueOf("builtin")})

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	if errMsg, hasError := resultMap["error"]; hasError {
		t.Fatalf("Failed to create scanner: %v", errMsg)
	}

	handle, hasHandle := resultMap["handle"]
	if !hasHandle {
		t.Fatal("Expected handle in result")
	}

	// Clean up
	closeScanner(js.Value{}, []js.Value{js.ValueOf(handle)})
}

// TestScannerWithCustomRules tests creating a scanner with custom rules JSON
func TestScannerWithCustomRules(t *testing.T) {
	rules := []*types.Rule{
		{
			ID:      "test-rule-1",
			Name:    "Test API Key",
			Pattern: `(?P<secret>AKIA[A-Z0-9]{16})`,
		},
	}

	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("Failed to marshal rules: %v", err)
	}

	result := newScanner(js.Value{}, []js.Value{js.ValueOf(string(rulesJSON))})

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	if errMsg, hasError := resultMap["error"]; hasError {
		t.Fatalf("Failed to create scanner: %v", errMsg)
	}

	handle := resultMap["handle"]
	closeScanner(js.Value{}, []js.Value{js.ValueOf(handle)})
}

// TestScanContent tests scanning content for secrets
func TestScanContent(t *testing.T) {
	// Create scanner with custom rule
	rules := []*types.Rule{
		{
			ID:      "test-aws-key",
			Name:    "AWS Access Key",
			Pattern: `(?P<secret>AKIA[A-Z0-9]{16})`,
		},
	}

	rulesJSON, _ := json.Marshal(rules)
	createResult := newScanner(js.Value{}, []js.Value{js.ValueOf(string(rulesJSON))})
	handle := createResult.(map[string]interface{})["handle"].(int)
	defer closeScanner(js.Value{}, []js.Value{js.ValueOf(handle)})

	// Test content with a fake AWS key
	content := "The API key is AKIAIOSFODNN7EXAMPLE"
	resultStr := scan(js.Value{}, []js.Value{
		js.ValueOf(handle),
		js.ValueOf(content),
		js.ValueOf("test-source"),
	})

	// Should return JSON string
	jsonStr, ok := resultStr.(string)
	if !ok {
		t.Fatalf("Expected string result, got %T: %v", resultStr, resultStr)
	}

	var result ScanResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}

	if len(result.Matches) == 0 {
		t.Error("Expected at least one match")
	}

	if result.Source != "test-source" {
		t.Errorf("Expected source 'test-source', got %q", result.Source)
	}
}

// TestScanBatch tests batch scanning multiple content items
func TestScanBatch(t *testing.T) {
	// Create scanner with custom rule
	rules := []*types.Rule{
		{
			ID:      "test-generic-secret",
			Name:    "Generic Secret",
			Pattern: `(?P<secret>secret_[a-zA-Z0-9]{10,})`,
		},
	}

	rulesJSON, _ := json.Marshal(rules)
	createResult := newScanner(js.Value{}, []js.Value{js.ValueOf(string(rulesJSON))})
	handle := createResult.(map[string]interface{})["handle"].(int)
	defer closeScanner(js.Value{}, []js.Value{js.ValueOf(handle)})

	// Create batch items
	items := []ContentItem{
		{
			Source:  "script:inline:1",
			Content: "const key = 'secret_abc1234567890'",
		},
		{
			Source:  "script:inline:2",
			Content: "nothing here",
		},
		{
			Source:  "storage:local:config",
			Content: `{"apiKey": "secret_xyz9876543210"}`,
		},
	}

	itemsJSON, _ := json.Marshal(items)
	resultStr := scanBatch(js.Value{}, []js.Value{
		js.ValueOf(handle),
		js.ValueOf(string(itemsJSON)),
	})

	jsonStr, ok := resultStr.(string)
	if !ok {
		t.Fatalf("Expected string result, got %T: %v", resultStr, resultStr)
	}

	var result BatchScanResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}

	if result.Total < 2 {
		t.Errorf("Expected at least 2 total matches, got %d", result.Total)
	}

	if len(result.Results) != 3 {
		t.Errorf("Expected 3 result items, got %d", len(result.Results))
	}
}

// TestGetBuiltinRules tests retrieving builtin rules
func TestGetBuiltinRules(t *testing.T) {
	result := getBuiltinRules(js.Value{}, nil)

	jsonStr, ok := result.(string)
	if !ok {
		// Check if it's an error
		if errMap, isMap := result.(map[string]interface{}); isMap {
			t.Fatalf("Got error: %v", errMap["error"])
		}
		t.Fatalf("Expected string result, got %T", result)
	}

	var rules []*types.Rule
	if err := json.Unmarshal([]byte(jsonStr), &rules); err != nil {
		t.Fatalf("Failed to parse rules: %v", err)
	}

	if len(rules) == 0 {
		t.Error("Expected at least one builtin rule")
	}

	// Verify rules have required fields
	for _, rule := range rules {
		if rule.ID == "" {
			t.Error("Rule missing ID")
		}
		if rule.Pattern == "" {
			t.Error("Rule missing Pattern")
		}
	}
}

// TestCloseScanner tests scanner cleanup
func TestCloseScanner(t *testing.T) {
	// Create scanner
	createResult := newScanner(js.Value{}, []js.Value{js.ValueOf("builtin")})
	handle := createResult.(map[string]interface{})["handle"].(int)

	// Close it
	closeResult := closeScanner(js.Value{}, []js.Value{js.ValueOf(handle)})
	if closeResult != nil {
		if errMap, ok := closeResult.(map[string]interface{}); ok {
			t.Fatalf("Close failed: %v", errMap["error"])
		}
	}

	// Try to use closed scanner - should error
	scanResult := scan(js.Value{}, []js.Value{
		js.ValueOf(handle),
		js.ValueOf("test"),
	})

	if errMap, ok := scanResult.(map[string]interface{}); ok {
		if _, hasError := errMap["error"]; !hasError {
			t.Error("Expected error when using closed scanner")
		}
	} else {
		t.Error("Expected error when using closed scanner")
	}
}

// TestInvalidHandle tests error handling for invalid scanner handles
func TestInvalidHandle(t *testing.T) {
	result := scan(js.Value{}, []js.Value{
		js.ValueOf(99999), // Invalid handle
		js.ValueOf("test"),
	})

	errMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected error map, got %T", result)
	}

	if _, hasError := errMap["error"]; !hasError {
		t.Error("Expected error for invalid handle")
	}
}
