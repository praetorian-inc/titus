package validator

import (
	"net/url"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestAllEmbeddedYAMLValidators_SchemaValid schema-validates EVERY embedded
// YAML validator. No network. This catches malformed defs the moment a new
// validators/*.yaml is added.
//
// Legacy files with incompatible schemas are skipped (documented inline).
// Pre-existing schema bugs fixed in this commit:
//   - airbrake.yaml: type query_param -> query, param_name -> query_param
//   - codacy.yaml: type api-token -> header, header -> header_name
func TestAllEmbeddedYAMLValidators_SchemaValid(t *testing.T) {
	entries, err := validatorsFS.ReadDir("validators")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	// knownAuth mirrors http.go applyAuth's switch cases.
	// Empty string ("") is valid per http.go:134 (same as "none" — no auth,
	// secret is embedded in URL or passed via custom headers).
	knownAuth := map[string]bool{
		"":       true, // no auth / custom headers
		"none":   true, // explicit no-auth (e.g. flickr: token in URL query)
		"bearer":  true,
		"basic":   true,
		"header":  true,
		"query":   true,
		"api_key": true,
	}

	// legacyFiles use an incompatible schema format (old kingfisher/blynk formats).
	// They produce empty or broken ValidatorsConfig entries and are excluded
	// until migrated to the current schema.
	legacyFiles := map[string]bool{
		"blynk.yaml":       true, // rule_id/valid_status schema
		"clay.yaml":        true, // request/response/classification schema
		"clojars.yaml":     true, // no rule_ids field
		"codeclimate.yaml": true, // root-level entry, no validators: wrapper
		"curl.yaml":        true, // placeholder/template, empty URLs
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if legacyFiles[e.Name()] {
			t.Logf("SKIP legacy-format: %s", e.Name())
			continue
		}

		data, err := validatorsFS.ReadFile("validators/" + e.Name())
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}

		var cfg ValidatorsConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("%s: parse: %v", e.Name(), err)
		}

		for _, d := range cfg.Validators {
			if len(d.RuleIDs) == 0 {
				t.Errorf("%s/%s: empty rule_ids", e.Name(), d.Name)
			}
			if !knownAuth[d.HTTP.Auth.Type] {
				t.Errorf("%s/%s: bad auth type %q (want one of: bearer, basic, header, query, api_key, none, or empty)", e.Name(), d.Name, d.HTTP.Auth.Type)
			}
			if len(d.HTTP.SuccessCodes) == 0 {
				t.Errorf("%s/%s: no success_codes", e.Name(), d.Name)
			}
			// URL must be non-empty. Template URLs (containing {{ or ${ ) are
			// valid: the host is filled at runtime from named capture groups.
			// Only validate parseable form for non-template URLs.
			if d.HTTP.URL == "" {
				t.Errorf("%s/%s: empty url", e.Name(), d.Name)
			} else if !strings.Contains(d.HTTP.URL, "{{") && !strings.Contains(d.HTTP.URL, "${") {
				if _, err := url.Parse(d.HTTP.URL); err != nil {
					t.Errorf("%s/%s: bad url %q: %v", e.Name(), d.Name, d.HTTP.URL, err)
				}
			}
			for _, sc := range d.HTTP.SuccessCodes { // success/failure must be disjoint
				for _, fc := range d.HTTP.FailureCodes {
					if sc == fc {
						t.Errorf("%s/%s: code %d in both success_codes and failure_codes", e.Name(), d.Name, sc)
					}
				}
			}
		}
	}
}
