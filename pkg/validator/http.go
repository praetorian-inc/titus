// pkg/validator/http.go
package validator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// HTTPValidator validates secrets via HTTP requests defined in YAML.
type HTTPValidator struct {
	def    ValidatorDef
	client *http.Client
}

// NewHTTPValidator creates a validator from a YAML definition.
func NewHTTPValidator(def ValidatorDef, client *http.Client) *HTTPValidator {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPValidator{
		def:    def,
		client: client,
	}
}

// Name returns the validator name.
func (v *HTTPValidator) Name() string {
	return v.def.Name
}

// CanValidate returns true if this validator handles the given rule ID.
func (v *HTTPValidator) CanValidate(ruleID string) bool {
	for _, rid := range v.def.RuleIDs {
		if rid == ruleID {
			return true
		}
	}
	return false
}

// Validate performs HTTP validation against the configured endpoint.
func (v *HTTPValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	// Extract secret from match
	secret, err := v.extractSecret(match)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, err.Error()), nil
	}

	// Substitute URL templates with named capture group values
	url := substituteTemplateVars(v.def.HTTP.URL, match.NamedGroups)

	// Build request with optional body (also substitute template vars)
	var body io.Reader
	if v.def.HTTP.Body != "" {
		body = strings.NewReader(substituteTemplateVars(v.def.HTTP.Body, match.NamedGroups))
	}
	req, err := http.NewRequestWithContext(ctx, v.def.HTTP.Method, url, body)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to create request: %v", err)), nil
	}

	// Apply auth
	if err := v.applyAuth(req, secret); err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, err.Error()), nil
	}

	// Apply custom headers (with template substitution)
	for _, h := range v.def.HTTP.Headers {
		req.Header.Set(h.Name, substituteTemplateVars(h.Value, match.NamedGroups))
	}

	// Execute request
	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { _ = resp.Body.Close() }()

	needBody := v.def.HTTP.SuccessBodyContains != "" || v.def.HTTP.FailureBodyContains != "" || len(v.def.HTTP.Pull.JSON) > 0
	var respBody []byte
	if needBody {
		reader := io.Reader(resp.Body)
		if v.def.HTTP.SuccessBodyContains == "" && v.def.HTTP.FailureBodyContains == "" {
			reader = io.LimitReader(resp.Body, 1<<20)
		}
		respBody, err = io.ReadAll(reader)
		if err != nil {
			return types.NewValidationResult(types.StatusUndetermined, 0, fmt.Sprintf("failed to read response body: %v", err)), nil
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	result := v.evaluateResponse(resp.StatusCode, respBody)
	v.pullThrough(result, resp.Header, respBody)
	return result, nil
}

func (v *HTTPValidator) pullThrough(result *types.ValidationResult, header http.Header, body []byte) {
	if result == nil || result.Status != types.StatusValid {
		return
	}
	if result.Details == nil {
		result.Details = make(map[string]string)
	}
	for _, name := range v.def.HTTP.Pull.Headers {
		if name == "" {
			continue
		}
		if val := strings.TrimSpace(header.Get(name)); val != "" {
			result.Details[name] = val
			result.Message += " (" + name + ": " + val + ")"
		}
	}
	for _, name := range v.def.HTTP.Pull.JSON {
		if name == "" {
			continue
		}
		if val := jsonFieldString(body, name); val != "" {
			result.Details[name] = val
			result.Message += " (" + name + ": " + val + ")"
		}
	}
}

func jsonFieldString(body []byte, field string) string {
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		return ""
	}
	raw, ok := obj[field]
	if !ok {
		return ""
	}
	switch t := raw.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				continue
			}
			if s = strings.TrimSpace(s); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return ""
	}
}

func (v *HTTPValidator) extractSecret(match *types.Match) (string, error) {
	groupName := v.def.HTTP.Auth.SecretGroup
	if groupName == "" {
		return "", fmt.Errorf("secret_group not specified in validator config")
	}

	// Try named capture groups first
	if match.NamedGroups != nil {
		if value, ok := match.NamedGroups[groupName]; ok {
			return string(value), nil
		}
	}

	// Fall back to positional capture groups for numeric secret_group values
	if idx, err := strconv.Atoi(groupName); err == nil {
		// secret_group "1" = Groups[0] (1-based index)
		zeroIdx := idx - 1
		if zeroIdx >= 0 && zeroIdx < len(match.Groups) {
			return string(match.Groups[zeroIdx]), nil
		}
		return "", fmt.Errorf("positional group %d out of range (have %d groups)", idx, len(match.Groups))
	}

	// List available groups for debugging
	available := make([]string, 0, len(match.NamedGroups))
	for name := range match.NamedGroups {
		available = append(available, name)
	}
	return "", fmt.Errorf("named group %q not found (available: %v)", groupName, available)
}

func (v *HTTPValidator) applyAuth(req *http.Request, secret string) error {
	switch v.def.HTTP.Auth.Type {
	case "none", "":
		// No authentication - URL itself may contain the secret (e.g., Slack webhooks)
		return nil

	case "bearer":
		req.Header.Set("Authorization", "Bearer "+secret)

	case "basic":
		username := v.def.HTTP.Auth.Username
		if username == "" {
			username = secret // Secret is the username if not specified
		}
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + secret))
		req.Header.Set("Authorization", "Basic "+auth)

	case "header":
		headerName := v.def.HTTP.Auth.HeaderName
		if headerName == "" {
			return fmt.Errorf("header auth requires header_name")
		}
		req.Header.Set(headerName, secret)

	case "query":
		paramName := v.def.HTTP.Auth.QueryParam
		if paramName == "" {
			return fmt.Errorf("query auth requires query_param")
		}
		q := req.URL.Query()
		q.Set(paramName, secret)
		req.URL.RawQuery = q.Encode()

	case "api_key":
		// Sets "Authorization: key=SECRET" or custom prefix
		// Used by Firebase FCM, Google APIs, etc.
		prefix := v.def.HTTP.Auth.KeyPrefix
		if prefix == "" {
			prefix = "key="
		}
		req.Header.Set("Authorization", prefix+secret)

	default:
		return fmt.Errorf("unsupported auth type: %s", v.def.HTTP.Auth.Type)
	}
	return nil
}

func (v *HTTPValidator) evaluateResponse(statusCode int, body []byte) *types.ValidationResult {
	bodyStr := string(body)

	// Check failure body first (takes precedence over success codes)
	if v.def.HTTP.FailureBodyContains != "" && strings.Contains(bodyStr, v.def.HTTP.FailureBodyContains) {
		return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("HTTP %d - response body indicates invalid credentials", statusCode))
	}

	// Check success codes
	for _, code := range v.def.HTTP.SuccessCodes {
		if statusCode == code {
			// If success_body_contains is specified, also check the body
			if v.def.HTTP.SuccessBodyContains != "" {
				if strings.Contains(bodyStr, v.def.HTTP.SuccessBodyContains) {
					return types.NewValidationResult(types.StatusValid, 1.0, fmt.Sprintf("HTTP %d - credentials accepted", statusCode))
				}
				// Status code matched but body didn't - treat as invalid
				return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("HTTP %d - response body indicates invalid credentials", statusCode))
			}
			return types.NewValidationResult(types.StatusValid, 1.0, fmt.Sprintf("HTTP %d - credentials accepted", statusCode))
		}
	}

	// Check failure codes
	for _, code := range v.def.HTTP.FailureCodes {
		if statusCode == code {
			return types.NewValidationResult(types.StatusInvalid, 1.0, fmt.Sprintf("HTTP %d - credentials rejected", statusCode))
		}
	}

	// Unknown status code
	return types.NewValidationResult(types.StatusUndetermined, 0.5, fmt.Sprintf("HTTP %d - unexpected status code", statusCode))
}

// substituteTemplateVars replaces template variables in s using named capture groups.
// Handles all common template syntaxes: {{name}}, {{ name }}, {{.name}}, {{ .name }}
func substituteTemplateVars(s string, groups map[string][]byte) string {
	for name, value := range groups {
		val := string(value)
		s = strings.ReplaceAll(s, "{{"+name+"}}", val)
		s = strings.ReplaceAll(s, "{{ "+name+" }}", val)
		s = strings.ReplaceAll(s, "{{."+name+"}}", val)
		s = strings.ReplaceAll(s, "{{ ."+name+" }}", val)
	}
	return s
}
