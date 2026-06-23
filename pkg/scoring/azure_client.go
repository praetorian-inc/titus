package scoring

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type azureCredentials struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

func (c *azureCredentials) complete() bool {
	return c.TenantID != "" && c.ClientID != "" && c.ClientSecret != ""
}

type azureSubscription struct {
	ID          string `json:"subscriptionId"`
	DisplayName string `json:"displayName"`
}

type azureRoleAssignment struct {
	RoleDefinitionID string
	Scope            string
}

type azureAppRoleAssignment struct {
	AppRoleID           string
	ResourceDisplayName string
}

const (
	azureRoleOwner            = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	azureRoleContributor      = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	azureRoleReader           = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	azureRoleKVAdmin          = "00482a5a-887f-4fb3-b363-3b7fe8e74483"
	azureRoleKVSecretsOfficer = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7" // #nosec G101 -- Azure RBAC role definition GUID, not a credential.
	azureRoleKVSecretsUser    = "4633458b-17de-408a-b874-0445c86b69e6" // #nosec G101 -- Azure RBAC role definition GUID, not a credential.
)

const (
	azureDirRoleGlobalAdmin   = "62e90394-69f5-4237-9190-012177145e10"
	azureDirRolePrivRoleAdmin = "e8611ab8-c189-46e8-94e1-60213ab1f814"
)

// Microsoft Graph application permission GUIDs considered minimal/read-only.
var graphMinimalAppRoles = map[string]bool{
	"df021288-bdef-4463-88db-98f22de89214": true, // User.Read.All
	"97235f07-e226-4f63-ace3-39588e11d3a1": true, // User.ReadBasic.All
	"e1fe6dd8-ba31-4d61-89e7-88639da4683d": true, // User.Read
	"00000000-0000-0000-0000-000000000000": true, // default access (no specific app role)
}

type azureAPI interface {
	ListSubscriptions(ctx context.Context) ([]azureSubscription, error)
	ListRoleAssignments(ctx context.Context, subscriptionID string) ([]azureRoleAssignment, error)
	GetDirectoryRoleMemberships(ctx context.Context) ([]string, error)
	GetAppRoleAssignments(ctx context.Context) ([]azureAppRoleAssignment, error)
}

type azureClientFactory func(ctx context.Context, creds *azureCredentials) (azureAPI, error)

func defaultAzureClientFactory(ctx context.Context, creds *azureCredentials) (azureAPI, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	armToken, err := azureAcquireToken(ctx, client, creds, "https://management.azure.com/.default")
	if err != nil {
		return nil, err
	}

	objectID, err := extractObjectIDFromJWT(armToken)
	if err != nil {
		return nil, fmt.Errorf("extract object ID: %w", err)
	}

	// Graph token failure is non-fatal; directory role conditions just won't fire.
	graphToken, _ := azureAcquireToken(ctx, client, creds, "https://graph.microsoft.com/.default")

	return &azureHTTPAPI{
		client:     client,
		armToken:   armToken,
		graphToken: graphToken,
		objectID:   objectID,
	}, nil
}

func azureAcquireToken(ctx context.Context, client *http.Client, creds *azureCredentials, scope string) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", creds.TenantID)

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {creds.ClientID},
		"client_secret": {creds.ClientSecret},
		"scope":         {scope},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Description != "" {
			return "", fmt.Errorf("%s: %s", errResp.Error, errResp.Description)
		}
		return "", fmt.Errorf("token request: HTTP %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}
	return tokenResp.AccessToken, nil
}

func extractObjectIDFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims struct {
		OID string `json:"oid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parse JWT claims: %w", err)
	}
	if claims.OID == "" {
		return "", fmt.Errorf("oid claim missing from token")
	}
	return claims.OID, nil
}

type azureHTTPAPI struct {
	client     *http.Client
	armToken   string
	graphToken string
	objectID   string
}

// maxPages caps pagination to avoid infinite loops.
const maxPages = 10

// paginatedResponse holds the raw JSON value array and the next page link.
type paginatedResponse struct {
	Value    json.RawMessage `json:"value"`
	NextLink string          `json:"nextLink"`
	// Graph API uses @odata.nextLink instead of nextLink.
	ODataNextLink string `json:"@odata.nextLink"`
}

func (p *paginatedResponse) nextURL() string {
	if p.NextLink != "" {
		return p.NextLink
	}
	return p.ODataNextLink
}

// fetchAllPages fetches the initial URL and follows pagination links, returning
// the concatenated raw JSON value arrays. The caller is responsible for
// unmarshaling each element.
func (a *azureHTTPAPI) fetchAllPages(ctx context.Context, initialURL, token string) ([]json.RawMessage, error) {
	var allValues []json.RawMessage

	currentURL := initialURL
	for page := 0; page < maxPages; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			return allValues, err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := a.client.Do(req)
		if err != nil {
			return allValues, err
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return allValues, err
		}
		if resp.StatusCode != http.StatusOK {
			return allValues, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		var pageResp paginatedResponse
		if err := json.Unmarshal(body, &pageResp); err != nil {
			return allValues, err
		}

		// Parse value array into individual raw elements.
		var items []json.RawMessage
		if err := json.Unmarshal(pageResp.Value, &items); err != nil {
			return allValues, err
		}
		allValues = append(allValues, items...)

		next := pageResp.nextURL()
		if next == "" {
			break
		}
		currentURL = next
	}

	return allValues, nil
}

func (a *azureHTTPAPI) ListSubscriptions(ctx context.Context) ([]azureSubscription, error) {
	u := "https://management.azure.com/subscriptions?api-version=2020-01-01"
	items, err := a.fetchAllPages(ctx, u, a.armToken)
	if err != nil {
		return nil, fmt.Errorf("listSubscriptions: %w", err)
	}

	subs := make([]azureSubscription, 0, len(items))
	for _, raw := range items {
		var s azureSubscription
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		subs = append(subs, s)
	}
	return subs, nil
}

func (a *azureHTTPAPI) ListRoleAssignments(ctx context.Context, subscriptionID string) ([]azureRoleAssignment, error) {
	filter := url.QueryEscape(fmt.Sprintf("principalId eq '%s'", a.objectID))
	u := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=%s",
		subscriptionID, filter)

	items, err := a.fetchAllPages(ctx, u, a.armToken)
	if err != nil {
		return nil, fmt.Errorf("listRoleAssignments: %w", err)
	}

	assignments := make([]azureRoleAssignment, 0, len(items))
	for _, raw := range items {
		var v struct {
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				Scope            string `json:"scope"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		roleID := v.Properties.RoleDefinitionID
		if idx := strings.LastIndex(roleID, "/"); idx >= 0 {
			roleID = roleID[idx+1:]
		}
		assignments = append(assignments, azureRoleAssignment{
			RoleDefinitionID: roleID,
			Scope:            v.Properties.Scope,
		})
	}
	return assignments, nil
}

func (a *azureHTTPAPI) GetDirectoryRoleMemberships(ctx context.Context) ([]string, error) {
	if a.graphToken == "" {
		return nil, fmt.Errorf("no graph token")
	}

	u := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/servicePrincipals/%s/memberOf/microsoft.graph.directoryRole",
		a.objectID)

	items, err := a.fetchAllPages(ctx, u, a.graphToken)
	if err != nil {
		return nil, fmt.Errorf("getDirectoryRoles: %w", err)
	}

	roles := make([]string, 0, len(items))
	for _, raw := range items {
		var v struct {
			RoleTemplateID string `json:"roleTemplateId"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		if v.RoleTemplateID != "" {
			roles = append(roles, v.RoleTemplateID)
		}
	}
	return roles, nil
}

func (a *azureHTTPAPI) GetAppRoleAssignments(ctx context.Context) ([]azureAppRoleAssignment, error) {
	if a.graphToken == "" {
		return nil, fmt.Errorf("no graph token")
	}

	u := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/servicePrincipals/%s/appRoleAssignments",
		a.objectID)

	items, err := a.fetchAllPages(ctx, u, a.graphToken)
	if err != nil {
		return nil, fmt.Errorf("getAppRoleAssignments: %w", err)
	}

	assignments := make([]azureAppRoleAssignment, 0, len(items))
	for _, raw := range items {
		var v struct {
			AppRoleID           string `json:"appRoleId"`
			ResourceDisplayName string `json:"resourceDisplayName"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		assignments = append(assignments, azureAppRoleAssignment{
			AppRoleID:           v.AppRoleID,
			ResourceDisplayName: v.ResourceDisplayName,
		})
	}
	return assignments, nil
}
