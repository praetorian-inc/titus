// Package auth provides OAuth authentication flows for Microsoft Entra ID
// (Azure AD) that any Microsoft-based Titus subcommand can share.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// AzurePowerShellClientID is a well-known first-party public client.
	// Widely used in pentest tools (GraphRunner, ROADtools, etc.) because it's
	// pre-consented for Graph API scopes in most tenants.
	AzurePowerShellClientID = "1950a258-227b-4e31-a9cf-717495945fc2"

	// GraphCLIClientID is the Microsoft Graph Command Line Tools public client.
	GraphCLIClientID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

	// DefaultTenantID is used for multi-tenant auth against organizational accounts.
	DefaultTenantID = "organizations"

	// httpTimeout is the per-request HTTP timeout for OAuth calls.
	httpTimeout = 30 * time.Second
)

// DeviceCodeResult contains the tokens returned after successful authentication.
type DeviceCodeResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	Scope        string
	TokenType    string
}

// deviceCodeResponse is the JSON response from the /devicecode endpoint.
type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

// tokenResponse is the JSON response from the /token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// tokenEndpoint returns the OAuth 2.0 token endpoint for the given tenant.
func tokenEndpoint(tenantID string) string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
}

// deviceCodeEndpoint returns the device code endpoint for the given tenant.
func deviceCodeEndpoint(tenantID string) string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode", tenantID)
}

// DeviceCodeAuth performs the OAuth 2.0 device code flow against Microsoft Entra ID.
// It prints a message to the provided writer instructing the user to authenticate,
// then polls until the user completes authentication or the code expires.
//
// Parameters:
//   - ctx: context for cancellation
//   - clientID: Azure AD application (client) ID
//   - tenantID: Azure AD tenant ID ("organizations" for multi-tenant, "common" for any)
//   - scopes: OAuth scopes to request (e.g., "https://graph.microsoft.com/.default")
//   - output: writer for user-facing messages (the "go to this URL" prompt)
func DeviceCodeAuth(ctx context.Context, clientID, tenantID string, scopes []string, output io.Writer) (*DeviceCodeResult, error) {
	client := &http.Client{Timeout: httpTimeout}

	// Step 1: Request a device code.
	dcResp, err := requestDeviceCode(ctx, client, clientID, tenantID, scopes)
	if err != nil {
		return nil, fmt.Errorf("requesting device code: %w", err)
	}

	// Print the user-facing message.
	_, _ = fmt.Fprintln(output, dcResp.Message)

	// Step 2: Poll for token.
	interval := time.Duration(dcResp.Interval) * time.Second
	if interval == 0 {
		interval = 5 * time.Second
	}

	deadline := time.Now().Add(time.Duration(dcResp.ExpiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("device code expired")
		}

		result, pollErr := pollForToken(ctx, client, clientID, tenantID, dcResp.DeviceCode)
		if pollErr != nil {
			return nil, pollErr
		}

		if result != nil {
			return result, nil
		}

		// result == nil && pollErr == nil means authorization_pending, continue polling.
	}
}

// requestDeviceCode sends a POST to the /devicecode endpoint and parses the response.
func requestDeviceCode(ctx context.Context, client *http.Client, clientID, tenantID string, scopes []string) (*deviceCodeResponse, error) {
	endpoint := deviceCodeEndpoint(tenantID)

	data := url.Values{
		"client_id": {clientID},
		"scope":     {strings.Join(scopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var dcResp deviceCodeResponse
	if err := json.Unmarshal(body, &dcResp); err != nil {
		return nil, fmt.Errorf("parsing device code response: %w", err)
	}

	if dcResp.DeviceCode == "" {
		return nil, fmt.Errorf("empty device_code in response")
	}

	return &dcResp, nil
}

// pollForToken sends a single token poll request.
//
// Returns:
//   - (*DeviceCodeResult, nil) on success
//   - (nil, nil) when authorization is still pending (caller should keep polling)
//   - (nil, error) on terminal errors (expired, declined, network)
func pollForToken(ctx context.Context, client *http.Client, clientID, tenantID, deviceCode string) (*DeviceCodeResult, error) {
	endpoint := tokenEndpoint(tenantID)

	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {clientID},
		"device_code": {deviceCode},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	switch tokenResp.Error {
	case "":
		// Success.
		return &DeviceCodeResult{
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			ExpiresIn:    tokenResp.ExpiresIn,
			Scope:        tokenResp.Scope,
			TokenType:    tokenResp.TokenType,
		}, nil
	case "authorization_pending":
		return nil, nil
	case "slow_down":
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
		return nil, nil
	case "expired_token":
		return nil, fmt.Errorf("device code expired: %s", tokenResp.ErrorDesc)
	case "authorization_declined":
		return nil, fmt.Errorf("authorization declined: %s", tokenResp.ErrorDesc)
	default:
		return nil, fmt.Errorf("token error %q: %s", tokenResp.Error, tokenResp.ErrorDesc)
	}
}

// RefreshToken exchanges a refresh token for a new access token.
func RefreshToken(ctx context.Context, clientID, tenantID, refreshToken string, scopes []string) (*DeviceCodeResult, error) {
	client := &http.Client{Timeout: httpTimeout}
	endpoint := tokenEndpoint(tenantID)

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
		"scope":         {strings.Join(scopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending refresh request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading refresh response: %w", err)
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing refresh response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("refresh token error %q: %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	return &DeviceCodeResult{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        tokenResp.Scope,
		TokenType:    tokenResp.TokenType,
	}, nil
}

// CachedToken is the on-disk representation of a cached Microsoft OAuth token.
type CachedToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ClientID     string    `json:"client_id"`
	TenantID     string    `json:"tenant_id"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// TokenCachePath returns the path to the Microsoft token cache file (~/.titus/microsoft_token.json).
func TokenCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determining home directory: %w", err)
	}
	return filepath.Join(home, ".titus", "microsoft_token.json"), nil
}

// SaveCachedToken writes the token result to the cache file at ~/.titus/microsoft_token.json.
func SaveCachedToken(result *DeviceCodeResult, clientID, tenantID string) error {
	cachePath, err := TokenCachePath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	cached := CachedToken{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ClientID:     clientID,
		TenantID:     tenantID,
		ExpiresAt:    time.Now().Add(time.Duration(result.ExpiresIn) * time.Second),
	}

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cached token: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(cachePath), ".microsoft_token_*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("setting permissions: %w", err)
	}
	if err := os.Rename(tmpName, cachePath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("renaming cache file: %w", err)
	}
	return nil
}

// LoadCachedToken reads the cached token from ~/.titus/microsoft_token.json.
func LoadCachedToken() (*CachedToken, error) {
	cachePath, err := TokenCachePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(cachePath) // #nosec G304 -- path is constructed from UserHomeDir + hardcoded filename, not user input
	if err != nil {
		return nil, fmt.Errorf("reading cached token: %w", err)
	}

	var cached CachedToken
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, fmt.Errorf("parsing cached token: %w", err)
	}

	return &cached, nil
}
