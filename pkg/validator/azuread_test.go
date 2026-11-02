package validator

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	azureADTestClientID = "11111111-2222-3333-4444-555555555555"
	azureADTestTenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	azureADTestSecret   = "ArE8Q~1pQL_W_8IZiTnG6TNB-.kGWlfzN61fUa2U"
)

func TestAzureADValidator_Name(t *testing.T) {
	assert.Equal(t, "azure-ad", NewAzureADValidator().Name())
}

func TestAzureADValidator_CanValidate(t *testing.T) {
	v := NewAzureADValidator()
	assert.True(t, v.CanValidate("np.azure.7"))
	assert.True(t, v.CanValidate("np.azure.8"))
	assert.False(t, v.CanValidate("np.azure.1"))
	assert.False(t, v.CanValidate("np.azure.3"))
	assert.False(t, v.CanValidate("np.github.1"))
}

func TestAzureADValidator_ExtractCredentials_IdaWebConfig(t *testing.T) {
	v := NewAzureADValidator()
	match := azureADMatch(types.Snippet{
		Before:   []byte(`<add key="ida:ClientId" value="` + azureADTestClientID + `" />`),
		Matching: []byte(`<add key="ida:AppSecret" value="` + azureADTestSecret + `" />`),
		After:    []byte(`<add key="ida:TenantId" value="` + azureADTestTenantID + `" />`),
	})

	clientID, secret, tenantID, err := v.extractCredentials(match)
	require.NoError(t, err)
	assert.Equal(t, azureADTestClientID, clientID)
	assert.Equal(t, azureADTestSecret, secret)
	assert.Equal(t, azureADTestTenantID, tenantID)
}

func TestAzureADValidator_ExtractCredentials_IdaAppID(t *testing.T) {
	v := NewAzureADValidator()
	match := azureADMatch(types.Snippet{
		Before: []byte(`<add key="ida:AppID" value="` + azureADTestClientID + `"/>
<add key="ida:TenantID" value="` + azureADTestTenantID + `"/>`),
		Matching: []byte(`<add key="client_secret" value="` + azureADTestSecret + `" />`),
	})

	clientID, secret, tenantID, err := v.extractCredentials(match)
	require.NoError(t, err)
	assert.Equal(t, azureADTestClientID, clientID)
	assert.Equal(t, azureADTestSecret, secret)
	assert.Equal(t, azureADTestTenantID, tenantID)
}

func TestAzureADValidator_ExtractCredentials_WebsiteAuth(t *testing.T) {
	v := NewAzureADValidator()
	match := azureADMatch(types.Snippet{
		Before: []byte(`WEBSITE_AUTH_CLIENT_ID=` + azureADTestClientID + `
WEBSITE_AUTH_OPENID_ISSUER=https://login.microsoftonline.com/` + azureADTestTenantID + `/v2.0`),
		Matching: []byte(`WEBSITE_AUTH_CLIENT_SECRET=` + azureADTestSecret),
	})

	clientID, secret, tenantID, err := v.extractCredentials(match)
	require.NoError(t, err)
	assert.Equal(t, azureADTestClientID, clientID)
	assert.Equal(t, azureADTestSecret, secret)
	assert.Equal(t, azureADTestTenantID, tenantID)
}

func TestAzureADValidator_ExtractCredentials_CSharpAppId(t *testing.T) {
	v := NewAzureADValidator()
	match := azureADMatch(types.Snippet{
		Before: []byte(`String appId = "` + azureADTestClientID + `";
string tenantId = "` + azureADTestTenantID + `";`),
		Matching: []byte(`String clientSecret = "` + azureADTestSecret + `";`),
	})

	clientID, secret, tenantID, err := v.extractCredentials(match)
	require.NoError(t, err)
	assert.Equal(t, azureADTestClientID, clientID)
	assert.Equal(t, azureADTestSecret, secret)
	assert.Equal(t, azureADTestTenantID, tenantID)
}

func TestAzureADValidator_ExtractCredentials_EnvVars(t *testing.T) {
	v := NewAzureADValidator()
	match := azureADMatch(types.Snippet{
		Before:   []byte("AZURE_TENANT_ID=" + azureADTestTenantID + "\nAZURE_CLIENT_ID=" + azureADTestClientID + "\n"),
		Matching: []byte("AZURE_CLIENT_SECRET=" + azureADTestSecret),
	})

	clientID, secret, tenantID, err := v.extractCredentials(match)
	require.NoError(t, err)
	assert.Equal(t, azureADTestClientID, clientID)
	assert.Equal(t, azureADTestSecret, secret)
	assert.Equal(t, azureADTestTenantID, tenantID)
}

func TestAzureADValidator_ExtractCredentials_StsIssuer(t *testing.T) {
	v := NewAzureADValidator()
	match := azureADMatch(types.Snippet{
		Before: []byte(`client_id=` + azureADTestClientID + `
Issuer=https://sts.windows.net/` + azureADTestTenantID + `/`),
		Matching: []byte(azureADTestSecret),
	})

	clientID, _, tenantID, err := v.extractCredentials(match)
	require.NoError(t, err)
	assert.Equal(t, azureADTestClientID, clientID)
	assert.Equal(t, azureADTestTenantID, tenantID)
}

func TestAzureADValidator_ExtractCredentials_MissingSecret(t *testing.T) {
	v := NewAzureADValidator()
	_, _, _, err := v.extractCredentials(&types.Match{
		RuleID:      "np.azure.7",
		NamedGroups: map[string][]byte{},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client_secret")
}

func TestAzureADValidator_ExtractCredentials_MissingClientID(t *testing.T) {
	v := NewAzureADValidator()
	_, _, _, err := v.extractCredentials(azureADMatch(types.Snippet{
		Matching: []byte("AZURE_CLIENT_SECRET=" + azureADTestSecret),
		After:    []byte("AZURE_TENANT_ID=" + azureADTestTenantID),
	}))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client_id")
}

func TestAzureADValidator_ExtractCredentials_MissingTenantID(t *testing.T) {
	v := NewAzureADValidator()
	_, _, _, err := v.extractCredentials(azureADMatch(types.Snippet{
		Before:   []byte("AZURE_CLIENT_ID=" + azureADTestClientID),
		Matching: []byte("AZURE_CLIENT_SECRET=" + azureADTestSecret),
	}))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id")
}

func TestAzureADValidator_Validate_Valid(t *testing.T) {
	var gotPath string
	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3599,"access_token":"tok"}`))
	}))
	defer server.Close()

	v := NewAzureADValidatorWithClient(&http.Client{Transport: &azureADMockTransport{server: server}})
	result, err := v.Validate(context.Background(), azureADCompleteMatch())
	require.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, azureADTestClientID)
	assert.Equal(t, "/"+azureADTestTenantID+"/oauth2/v2.0/token", gotPath)
	assert.Equal(t, "client_credentials", gotForm.Get("grant_type"))
	assert.Equal(t, azureADTestClientID, gotForm.Get("client_id"))
	assert.Equal(t, azureADTestSecret, gotForm.Get("client_secret"))
	assert.Equal(t, "https://graph.microsoft.com/.default", gotForm.Get("scope"))
}

func TestAzureADValidator_Validate_InvalidSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_codes":[7000215],"error_description":"AADSTS7000215: Invalid client secret provided. Trace ID: abc"}`))
	}))
	defer server.Close()

	v := NewAzureADValidatorWithClient(&http.Client{Transport: &azureADMockTransport{server: server}})
	result, err := v.Validate(context.Background(), azureADCompleteMatch())
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Equal(t, 1.0, result.Confidence)
	assert.Contains(t, result.Message, "AADSTS7000215")
	assert.NotContains(t, result.Message, "Trace ID")
}

func TestAzureADValidator_Validate_DisabledApp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unauthorized_client","error_codes":[7000112],"error_description":"AADSTS7000112: Application is disabled."}`))
	}))
	defer server.Close()

	v := NewAzureADValidatorWithClient(&http.Client{Transport: &azureADMockTransport{server: server}})
	result, err := v.Validate(context.Background(), azureADCompleteMatch())
	require.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
	assert.Contains(t, result.Message, "AADSTS7000112")
}

func TestAzureADValidator_Validate_Undetermined_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewAzureADValidatorWithClient(&http.Client{Transport: &azureADMockTransport{server: server}})
	result, err := v.Validate(context.Background(), azureADCompleteMatch())
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestAzureADValidator_Validate_PartialCredentials(t *testing.T) {
	v := NewAzureADValidator()
	result, err := v.Validate(context.Background(), azureADMatch(types.Snippet{
		Matching: []byte("AZURE_CLIENT_SECRET=" + azureADTestSecret),
	}))
	require.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "cannot validate")
}

func TestAzureADValidator_DefaultEngineRegisters(t *testing.T) {
	engine := NewDefaultEngine(1)
	assert.True(t, engine.CanValidate("np.azure.7"))
	assert.True(t, engine.CanValidate("np.azure.8"))
}

func azureADMatch(snippet types.Snippet) *types.Match {
	return &types.Match{
		RuleID: "np.azure.7",
		NamedGroups: map[string][]byte{
			"client_secret": []byte(azureADTestSecret),
		},
		Snippet: snippet,
	}
}

func azureADCompleteMatch() *types.Match {
	return azureADMatch(types.Snippet{
		Before:   []byte("AZURE_TENANT_ID=" + azureADTestTenantID + "\nAZURE_CLIENT_ID=" + azureADTestClientID + "\n"),
		Matching: []byte("AZURE_CLIENT_SECRET=" + azureADTestSecret),
	})
}

type azureADMockTransport struct {
	server *httptest.Server
}

func (t *azureADMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}

func TestAzureADErrorSummary_StripsTrace(t *testing.T) {
	got := azureADErrorSummary("invalid_client", "AADSTS7000215: Invalid client secret provided. Trace ID: abc", []int{7000215})
	assert.Equal(t, "AADSTS7000215: Invalid client secret provided.", got)
	assert.False(t, strings.Contains(got, "Trace ID"))
}
