package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

const azureGUID = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

// App Service / ASP.NET (ida:*) / Easy Auth / env / C# client IDs.
var azureADClientIDPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)key\s*=\s*["'](?:ida:)?(?:ClientId|AppID|AppId|ApplicationId|WEBSITE_AUTH_CLIENT_ID|AZURE_CLIENT_ID|ARM_CLIENT_ID|MicrosoftAppId)["'][^>]*value\s*=\s*["'](` + azureGUID + `)["']`),
	regexp.MustCompile(`(?i)(?:WEBSITE_AUTH_CLIENT_ID|AZURE_CLIENT_ID|ARM_CLIENT_ID|MicrosoftAppId|ida:ClientId|ida:AppID|ida:AppId)\s*["']?\s*[:=]\s*["']?(` + azureGUID + `)`),
	regexp.MustCompile(`(?i)(?:client[_-]?id|app[_-]?id|application[_-]?id)\s*["']?\s*[:=]\s*["']?(` + azureGUID + `)`),
	regexp.MustCompile(`(?i)(?:appId|clientId)\s*=\s*["'](` + azureGUID + `)["']`),
}

var azureADTenantIDPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)key\s*=\s*["'](?:ida:)?(?:TenantId|TenantID|AZURE_TENANT_ID|ARM_TENANT_ID)["'][^>]*value\s*=\s*["'](` + azureGUID + `)["']`),
	regexp.MustCompile(`(?i)login\.microsoftonline\.com/(` + azureGUID + `)`),
	regexp.MustCompile(`(?i)sts\.windows\.net/(` + azureGUID + `)`),
	regexp.MustCompile(`(?i)(?:WEBSITE_AUTH_OPENID_ISSUER|AZURE_TENANT_ID|ARM_TENANT_ID|ida:TenantId|ida:TenantID|tenant[_-]?id)\s*["']?\s*[:=]\s*["']?(` + azureGUID + `)`),
	regexp.MustCompile(`(?i)tenantId\s*=\s*["'](` + azureGUID + `)["']`),
}

// Azure errors that mean the client_id/secret pair cannot authenticate.
var azureADInvalidErrors = map[string]bool{
	"invalid_client":      true,
	"unauthorized_client": true,
}

var azureADInvalidCodes = map[int]bool{
	7000215: true, // invalid client secret
	700016:  true, // application not found
	7000112: true, // application disabled
	700027:  true, // invalid client assertion
}

// AzureADValidator live-checks Entra ID (Azure AD) app client_id+client_secret
// pairs discovered in App Service / ASP.NET config via the client_credentials
// token endpoint. Token request only — no Graph or ARM follow-up.
type AzureADValidator struct {
	client *http.Client
}

func NewAzureADValidator() *AzureADValidator {
	return &AzureADValidator{client: &http.Client{Timeout: 30 * time.Second}}
}

func NewAzureADValidatorWithClient(client *http.Client) *AzureADValidator {
	return &AzureADValidator{client: client}
}

func (v *AzureADValidator) Name() string { return "azure-ad" }

func (v *AzureADValidator) CanValidate(ruleID string) bool {
	return ruleID == "np.azure.7" || ruleID == "np.azure.8"
}

func (v *AzureADValidator) Validate(ctx context.Context, match *types.Match) (*types.ValidationResult, error) {
	clientID, clientSecret, tenantID, err := v.extractCredentials(match)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("cannot validate: %v", err),
		), nil
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to create request: %v", err),
		), nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("request failed: %v", err),
		), nil
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return types.NewValidationResult(
			types.StatusUndetermined,
			0,
			fmt.Sprintf("failed to read response: %v", err),
		), nil
	}

	return evaluateAzureADTokenResponse(resp.StatusCode, respBody, clientID), nil
}

func (v *AzureADValidator) extractCredentials(match *types.Match) (clientID, clientSecret, tenantID string, err error) {
	clientSecret = extractNamedGroup(match, "client_secret", "secret")
	if clientSecret == "" {
		return "", "", "", fmt.Errorf("client_secret not found in named groups")
	}

	clientID = searchSnippet(match.Snippet, azureADClientIDPatterns)
	if clientID == "" {
		return "", "", "", fmt.Errorf("partial credentials: found client secret but client_id not in context")
	}

	tenantID = searchSnippet(match.Snippet, azureADTenantIDPatterns)
	if tenantID == "" {
		return "", "", "", fmt.Errorf("partial credentials: found client_id but tenant_id not in context")
	}

	return clientID, clientSecret, tenantID, nil
}

func evaluateAzureADTokenResponse(status int, body []byte, clientID string) *types.ValidationResult {
	var parsed struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorCodes       []int  `json:"error_codes"`
	}
	_ = json.Unmarshal(body, &parsed)

	if status == http.StatusOK && parsed.AccessToken != "" {
		return types.NewValidationResult(
			types.StatusValid,
			1.0,
			fmt.Sprintf("valid Azure AD client credentials for %s", clientID),
		)
	}

	if azureADInvalidErrors[parsed.Error] {
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("credentials rejected: %s", azureADErrorSummary(parsed.Error, parsed.ErrorDescription, parsed.ErrorCodes)),
		)
	}
	for _, code := range parsed.ErrorCodes {
		if azureADInvalidCodes[code] {
			return types.NewValidationResult(
				types.StatusInvalid,
				1.0,
				fmt.Sprintf("credentials rejected: %s", azureADErrorSummary(parsed.Error, parsed.ErrorDescription, parsed.ErrorCodes)),
			)
		}
	}

	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return types.NewValidationResult(
			types.StatusInvalid,
			1.0,
			fmt.Sprintf("credentials rejected: HTTP %d", status),
		)
	}

	return types.NewValidationResult(
		types.StatusUndetermined,
		0.5,
		fmt.Sprintf("unexpected status code: HTTP %d", status),
	)
}

func azureADErrorSummary(errName, description string, codes []int) string {
	if description != "" {
		if i := strings.Index(description, "\r"); i > 0 {
			description = description[:i]
		}
		if i := strings.Index(description, " Trace ID:"); i > 0 {
			description = description[:i]
		}
		return strings.TrimSpace(description)
	}
	if errName != "" {
		return errName
	}
	if len(codes) > 0 {
		return fmt.Sprintf("AADSTS%d", codes[0])
	}
	return "invalid client credentials"
}
