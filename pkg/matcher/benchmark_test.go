//go:build !wasm

package matcher

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Benchmark comparing Hyperscan (CGO) vs regexp2 (non-CGO) performance.
//
// Test methodology:
// - Initialization time: NewHyperscan vs NewPortableRegexp
// - Scanning performance: Various content sizes (1KB, 10KB, 100KB, 1MB)
// - Rule count impact: 1, 10, 50, 100 rules
// - Real-world workload: Builtin rules on realistic secrets

// generateTestContent creates test content with embedded secrets of specified size.
func generateTestContent(size int) []byte {
	secrets := []string{
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"STRIPE_KEY=sk_live_51HqJZfExampleKey123456789012345678901234",
		"GITHUB_TOKEN=ghp_exampleTokenWith40Characters123456789",
		"database_url=postgres://user:P@ssw0rd123!@localhost:5432/mydb",
		"api_key=AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe",
		"slack_webhook=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
		"jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"private_key=-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAw5...\n-----END RSA PRIVATE KEY-----",
		"oauth_token=ya29.A0ARrdaM...",
	}

	// Build content to reach target size
	var buf bytes.Buffer
	secretsBlock := strings.Join(secrets, "\n") + "\n"

	// Add secrets interspersed with filler text
	for buf.Len() < size {
		buf.WriteString(secretsBlock)
		// Add some filler to make it realistic
		buf.WriteString("# Configuration file\n")
		buf.WriteString("LOG_LEVEL=info\n")
		buf.WriteString("PORT=8080\n")
		buf.WriteString("# Some comments and normal code\n")
		buf.WriteString("function doSomething() {\n")
		buf.WriteString("  console.log('hello world');\n")
		buf.WriteString("}\n\n")
	}

	// Trim to exact size
	content := buf.Bytes()
	if len(content) > size {
		content = content[:size]
	}
	return content
}

// createSyntheticRules creates N test rules with varying pattern complexity.
func createSyntheticRules(count int) []*types.Rule {
	// Mix of simple and complex patterns
	patterns := []string{
		`AKIA[0-9A-Z]{16}`,                                                        // Simple: AWS key
		`sk_live_[0-9a-zA-Z]{24,}`,                                                // Simple: Stripe
		`ghp_[0-9a-zA-Z]{36,}`,                                                    // Simple: GitHub
		`(?i)(api[_-]?key|apikey)['"\s:=]+([a-zA-Z0-9+/]{32,})`,                  // Medium: generic API key
		`(?i)(password|passwd|pwd)['"\s:=]+([^\s'"]{8,})`,                        // Medium: password
		`postgres://([^:]+):([^@]+)@([^:]+):(\d+)/(\w+)`,                         // Complex: database URL
		`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]{100,}-----END`,        // Complex: private key
		`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`,                   // Medium: JWT
		`(?i)secret[_-]?key['"\s:=]+['"]?([a-zA-Z0-9+/]{32,})['"]?`,             // Medium: secret key
		`https://hooks\.slack\.com/services/[A-Z0-9]{9,}/[A-Z0-9]{9,}/[a-zA-Z0-9]{24,}`, // Complex: Slack webhook
	}

	var rules []*types.Rule
	for i := 0; i < count; i++ {
		pattern := patterns[i%len(patterns)]
		rules = append(rules, &types.Rule{
			ID:      fmt.Sprintf("test.%d", i+1),
			Name:    fmt.Sprintf("Test Rule %d", i+1),
			Pattern: pattern,
		})
	}
	return rules
}

// BenchmarkHyperscan_Init benchmarks Hyperscan matcher initialization.
func BenchmarkHyperscan_Init(b *testing.B) {
	if !hyperscanAvailable() {
		b.Skip("Hyperscan not available")
	}

	benchmarks := []struct {
		name      string
		ruleCount int
	}{
		{"1_rule", 1},
		{"10_rules", 10},
		{"50_rules", 50},
		{"100_rules", 100},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			rules := createSyntheticRules(bm.ruleCount)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				m, err := NewHyperscan(rules, 0)
				if err != nil {
					b.Fatalf("Failed to create Hyperscan matcher: %v", err)
				}
				_ = m.Close()
			}
		})
	}
}

// BenchmarkPortable_Init benchmarks portable regexp2 matcher initialization.
func BenchmarkPortable_Init(b *testing.B) {
	benchmarks := []struct {
		name      string
		ruleCount int
	}{
		{"1_rule", 1},
		{"10_rules", 10},
		{"50_rules", 50},
		{"100_rules", 100},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			rules := createSyntheticRules(bm.ruleCount)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				m, err := NewPortableRegexp(rules, 0)
				if err != nil {
					b.Fatalf("Failed to create portable matcher: %v", err)
				}
				_ = m.Close()
			}
		})
	}
}

// BenchmarkHyperscan_Scan benchmarks Hyperscan scanning with varying content sizes.
func BenchmarkHyperscan_Scan(b *testing.B) {
	if !hyperscanAvailable() {
		b.Skip("Hyperscan not available")
	}

	rules := createSyntheticRules(10)
	m, err := NewHyperscan(rules, 0)
	if err != nil {
		b.Fatalf("Failed to create matcher: %v", err)
	}
	defer m.Close()

	benchmarks := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"10KB", 10 * 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			content := generateTestContent(bm.size)
			b.SetBytes(int64(len(content)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := m.Match(content)
				if err != nil {
					b.Fatalf("Match failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkPortable_Scan benchmarks portable regexp2 scanning with varying content sizes.
func BenchmarkPortable_Scan(b *testing.B) {
	rules := createSyntheticRules(10)
	m, err := NewPortableRegexp(rules, 0)
	if err != nil {
		b.Fatalf("Failed to create matcher: %v", err)
	}
	defer m.Close()

	benchmarks := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"10KB", 10 * 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			content := generateTestContent(bm.size)
			b.SetBytes(int64(len(content)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := m.Match(content)
				if err != nil {
					b.Fatalf("Match failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkHyperscan_RuleCount benchmarks Hyperscan with varying rule counts.
func BenchmarkHyperscan_RuleCount(b *testing.B) {
	if !hyperscanAvailable() {
		b.Skip("Hyperscan not available")
	}

	content := generateTestContent(10 * 1024) // 10KB content

	benchmarks := []struct {
		name      string
		ruleCount int
	}{
		{"1_rule", 1},
		{"10_rules", 10},
		{"50_rules", 50},
		{"100_rules", 100},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			rules := createSyntheticRules(bm.ruleCount)
			m, err := NewHyperscan(rules, 0)
			if err != nil {
				b.Fatalf("Failed to create matcher: %v", err)
			}
			defer m.Close()

			b.SetBytes(int64(len(content)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := m.Match(content)
				if err != nil {
					b.Fatalf("Match failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkPortable_RuleCount benchmarks portable regexp2 with varying rule counts.
func BenchmarkPortable_RuleCount(b *testing.B) {
	content := generateTestContent(10 * 1024) // 10KB content

	benchmarks := []struct {
		name      string
		ruleCount int
	}{
		{"1_rule", 1},
		{"10_rules", 10},
		{"50_rules", 50},
		{"100_rules", 100},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			rules := createSyntheticRules(bm.ruleCount)
			m, err := NewPortableRegexp(rules, 0)
			if err != nil {
				b.Fatalf("Failed to create matcher: %v", err)
			}
			defer m.Close()

			b.SetBytes(int64(len(content)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := m.Match(content)
				if err != nil {
					b.Fatalf("Match failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkHyperscan_Builtin benchmarks Hyperscan with real builtin rules.
func BenchmarkHyperscan_Builtin(b *testing.B) {
	if !hyperscanAvailable() {
		b.Skip("Hyperscan not available")
	}

	// Load builtin rules
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		b.Fatalf("Failed to load builtin rules: %v", err)
	}
	if len(rules) == 0 {
		b.Skip("No builtin rules found")
	}

	m, err := NewHyperscan(rules, 0)
	if err != nil {
		b.Fatalf("Failed to create matcher: %v", err)
	}
	defer m.Close()

	// Use realistic content with embedded secrets
	content := generateTestContent(100 * 1024) // 100KB

	b.Logf("Benchmarking with %d builtin rules on %d bytes", len(rules), len(content))
	b.SetBytes(int64(len(content)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := m.Match(content)
		if err != nil {
			b.Fatalf("Match failed: %v", err)
		}
	}
}

// BenchmarkPortable_Builtin benchmarks portable regexp2 with real builtin rules.
func BenchmarkPortable_Builtin(b *testing.B) {
	// Load builtin rules
	loader := rule.NewLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		b.Fatalf("Failed to load builtin rules: %v", err)
	}
	if len(rules) == 0 {
		b.Skip("No builtin rules found")
	}

	m, err := NewPortableRegexp(rules, 0)
	if err != nil {
		b.Fatalf("Failed to create matcher: %v", err)
	}
	defer m.Close()

	// Use realistic content with embedded secrets
	content := generateTestContent(100 * 1024) // 100KB

	b.Logf("Benchmarking with %d builtin rules on %d bytes", len(rules), len(content))
	b.SetBytes(int64(len(content)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := m.Match(content)
		if err != nil {
			b.Fatalf("Match failed: %v", err)
		}
	}
}

// BenchmarkHyperscan_ColdStart benchmarks Hyperscan with repeated initialization + scan.
func BenchmarkHyperscan_ColdStart(b *testing.B) {
	if !hyperscanAvailable() {
		b.Skip("Hyperscan not available")
	}

	rules := createSyntheticRules(10)
	content := generateTestContent(10 * 1024)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m, err := NewHyperscan(rules, 0)
		if err != nil {
			b.Fatalf("Failed to create matcher: %v", err)
		}

		_, err = m.Match(content)
		if err != nil {
			b.Fatalf("Match failed: %v", err)
		}

		_ = m.Close()
	}
}

// BenchmarkPortable_ColdStart benchmarks portable regexp2 with repeated initialization + scan.
func BenchmarkPortable_ColdStart(b *testing.B) {
	rules := createSyntheticRules(10)
	content := generateTestContent(10 * 1024)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m, err := NewPortableRegexp(rules, 0)
		if err != nil {
			b.Fatalf("Failed to create matcher: %v", err)
		}

		_, err = m.Match(content)
		if err != nil {
			b.Fatalf("Match failed: %v", err)
		}

		_ = m.Close()
	}
}
