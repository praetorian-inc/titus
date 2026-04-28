package scoring

import (
	"encoding/json"
	"fmt"
	"strings"
)

// jsonGet evaluates a simple dot-notation path against JSON data.
// Path must start with ".": "." = root value, ".field" = top-level,
// ".a.b" = nested. Array indexing is not supported.
func jsonGet(data []byte, path string) (interface{}, error) {
	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if path == "." {
		return root, nil
	}

	// Strip leading "." and split
	parts := strings.Split(strings.TrimPrefix(path, "."), ".")
	cur := root
	for _, part := range parts {
		if part == "" {
			continue
		}
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("path %q: expected object at segment %q, got %T", path, part, cur)
		}
		val, exists := m[part]
		if !exists {
			return nil, fmt.Errorf("path %q: field %q not found", path, part)
		}
		cur = val
	}
	return cur, nil
}
