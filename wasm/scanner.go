//go:build wasm

package main

import (
	"encoding/json"
	"sync"
	"syscall/js"

	"github.com/praetorian-inc/titus/pkg/scanner"
)

var (
	scanners   = make(map[int]*scanner.Core)
	scannersMu sync.RWMutex
	nextID     int
)

// newScanner creates a new scanner with the given rules JSON.
// JS: TitusNewScanner(rulesJSON) -> handle (int) or error string
func newScanner(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{"error": "rulesJSON argument required"}
	}

	rulesJSON := args[0].String()

	// Create scanner core (uses cached builtin rules)
	core, err := scanner.NewCore(rulesJSON, scanner.NoopLogger{})
	if err != nil {
		return map[string]interface{}{"error": "failed to create scanner: " + err.Error()}
	}

	// Register scanner
	scannersMu.Lock()
	id := nextID
	nextID++
	scanners[id] = core
	scannersMu.Unlock()

	return map[string]interface{}{"handle": id}
}

// scan scans a single content string.
// JS: TitusScan(handle, content, source) -> JSON results or error
func scan(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{"error": "handle and content arguments required"}
	}

	handle := args[0].Int()
	content := args[1].String()
	source := ""
	if len(args) > 2 {
		source = args[2].String()
	}

	scannersMu.RLock()
	core, ok := scanners[handle]
	scannersMu.RUnlock()

	if !ok {
		return map[string]interface{}{"error": "invalid scanner handle"}
	}

	// Scan content
	result, err := core.Scan(content, source)
	if err != nil {
		return map[string]interface{}{"error": "scan failed: " + err.Error()}
	}

	// Return results as JSON
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return map[string]interface{}{"error": "failed to marshal results: " + err.Error()}
	}

	return string(jsonBytes)
}

// scanBatch scans multiple content items.
// JS: TitusScanBatch(handle, itemsJSON) -> JSON results or error
func scanBatch(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{"error": "handle and itemsJSON arguments required"}
	}

	handle := args[0].Int()
	itemsJSON := args[1].String()

	scannersMu.RLock()
	core, ok := scanners[handle]
	scannersMu.RUnlock()

	if !ok {
		return map[string]interface{}{"error": "invalid scanner handle"}
	}

	// Parse items
	var items []scanner.ContentItem
	if err := json.Unmarshal([]byte(itemsJSON), &items); err != nil {
		return map[string]interface{}{"error": "failed to parse items JSON: " + err.Error()}
	}

	// Scan batch
	batchResult, err := core.ScanBatch(items)
	if err != nil {
		return map[string]interface{}{"error": "batch scan failed: " + err.Error()}
	}

	// Return batch results as JSON
	jsonBytes, err := json.Marshal(batchResult)
	if err != nil {
		return map[string]interface{}{"error": "failed to marshal results: " + err.Error()}
	}

	return string(jsonBytes)
}

// closeScanner closes a scanner and releases resources.
// JS: TitusCloseScanner(handle)
func closeScanner(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{"error": "handle argument required"}
	}

	handle := args[0].Int()

	scannersMu.Lock()
	core, ok := scanners[handle]
	if ok {
		delete(scanners, handle)
	}
	scannersMu.Unlock()

	if !ok {
		return map[string]interface{}{"error": "invalid scanner handle"}
	}

	core.Close()

	return nil
}

// getBuiltinRules returns the built-in rules as JSON.
// JS: TitusGetBuiltinRules() -> JSON rules array
func getBuiltinRules(this js.Value, args []js.Value) interface{} {
	rules, err := scanner.GetBuiltinRules()
	if err != nil {
		return map[string]interface{}{"error": "failed to load builtin rules: " + err.Error()}
	}

	jsonBytes, err := json.Marshal(rules)
	if err != nil {
		return map[string]interface{}{"error": "failed to marshal rules: " + err.Error()}
	}

	return string(jsonBytes)
}
