package validator

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

var allowedGCPTokenHosts = map[string]bool{
	"oauth2.googleapis.com":    true,
	"accounts.google.com":      true,
	"www.googleapis.com":       true,
	"iamcredentials.googleapis.com": true,
}

type GCPValidator struct {
	client   *http.Client
	tokenURL string // test override: when set, replaces the token_uri from the service account JSON
}

func NewGCPValidator() *GCPValidator {
	return &GCPValidator{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func NewGCPValidatorWithClient(client *http.Client) *GCPValidator {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &GCPValidator{client: client}
}

func (v *GCPValidator) Name() string { return "gcp" }

func (v *GCPValidator) CanValidate(ruleID string) bool {
	switch ruleID {
	case "kingfisher.gcp.1", "kingfisher.gcp.3":
		return true
	}
	return false
}

func (v *GCPValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	switch match.RuleID {
	case "kingfisher.gcp.1":
		return v.validateServiceAccount(ctx, match)
	case "kingfisher.gcp.3":
		return types.NewValidationResult(types.StatusUndetermined, 0,
			"private key ID alone cannot be validated without the full service account JSON"), nil
	default:
		return types.NewValidationResult(types.StatusUndetermined, 0, "unknown rule ID"), nil
	}
}

type gcpServiceAccount struct {
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	TokenURI     string `json:"token_uri"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
}

func (v *GCPValidator) validateServiceAccount(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	jsonBlob := v.extractServiceAccountJSON(match)
	if jsonBlob == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			"cannot extract service account JSON from match"), nil
	}

	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(jsonBlob), &sa); err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			fmt.Sprintf("failed to parse service account JSON: %v", err)), nil
	}

	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			"service account JSON missing client_email or private_key"), nil
	}

	tokenURL := v.tokenURL
	if tokenURL == "" {
		tokenURL = sa.TokenURI
		if tokenURL == "" {
			tokenURL = "https://oauth2.googleapis.com/token"
		}

		if !isAllowedGCPTokenHost(tokenURL) {
			return types.NewValidationResult(types.StatusUndetermined, 0,
				"token_uri is not a recognized Google endpoint"), nil
		}
	}

	now := time.Now()
	jwtToken, err := v.buildJWT(sa.ClientEmail, tokenURL, sa.PrivateKey, now)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			fmt.Sprintf("failed to build JWT: %v", err)), nil
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwtToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			fmt.Sprintf("failed to create request: %v", err)), nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0,
			fmt.Sprintf("request failed: %v", err)), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	return v.evaluateTokenResponse(resp, sa.ClientEmail)
}

func (v *GCPValidator) evaluateTokenResponse(resp *http.Response, clientEmail string) (*types.ValidationResult, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return types.NewValidationResult(types.StatusUndetermined, 0.5,
			"failed to read token response"), nil
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		var tokenResp map[string]interface{}
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			return types.NewValidationResult(types.StatusUndetermined, 0.5,
				"token response is not valid JSON"), nil
		}
		if _, ok := tokenResp["access_token"]; !ok {
			return types.NewValidationResult(types.StatusUndetermined, 0.5,
				"token response missing access_token"), nil
		}
		return types.NewValidationResult(types.StatusValid, 1.0,
			fmt.Sprintf("GCP service account key valid for %s", clientEmail)), nil

	case resp.StatusCode == http.StatusBadRequest:
		var errResp map[string]interface{}
		if err := json.Unmarshal(body, &errResp); err == nil {
			if errDesc, ok := errResp["error_description"].(string); ok {
				if strings.Contains(errDesc, "Invalid JWT") ||
					strings.Contains(errDesc, "invalid_grant") {
					return types.NewValidationResult(types.StatusInvalid, 1.0,
						fmt.Sprintf("GCP service account key rejected: %s", errDesc)), nil
				}
			}
			if errType, ok := errResp["error"].(string); ok && errType == "invalid_grant" {
				return types.NewValidationResult(types.StatusInvalid, 1.0,
					"GCP service account key rejected: invalid_grant"), nil
			}
		}
		return types.NewValidationResult(types.StatusUndetermined, 0.5,
			fmt.Sprintf("token endpoint returned HTTP %d", resp.StatusCode)), nil

	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return types.NewValidationResult(types.StatusInvalid, 1.0,
			fmt.Sprintf("GCP credentials rejected: HTTP %d", resp.StatusCode)), nil

	default:
		return types.NewValidationResult(types.StatusUndetermined, 0.5,
			fmt.Sprintf("unexpected status %d from token endpoint", resp.StatusCode)), nil
	}
}

func (v *GCPValidator) extractServiceAccountJSON(match *types.Match) string {
	// Try named groups first (the regex captures as "service_account" or "service_account_nested")
	for _, name := range []string{"service_account", "service_account_nested"} {
		if val, ok := match.NamedGroups[name]; ok && len(val) > 0 {
			return string(val)
		}
	}
	// Fall back to the matching snippet
	if len(match.Snippet.Matching) > 0 {
		return string(match.Snippet.Matching)
	}
	return ""
}

func (v *GCPValidator) buildJWT(clientEmail, audience, privateKeyPEM string, now time.Time) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not RSA")
	}

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}

	claims := map[string]interface{}{
		"iss":   clientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64

	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %v", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

func isAllowedGCPTokenHost(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return allowedGCPTokenHosts[strings.ToLower(parsed.Hostname())]
}
