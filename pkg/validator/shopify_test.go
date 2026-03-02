// pkg/validator/shopify_test.go
package validator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestShopifyValidator_Name(t *testing.T) {
	v := NewShopifyValidator()
	assert.Equal(t, "shopify", v.Name())
}

func TestShopifyValidator_CanValidate(t *testing.T) {
	v := NewShopifyValidator()
	assert.True(t, v.CanValidate("np.shopify.3"))
	assert.True(t, v.CanValidate("np.shopify.4"))
	assert.True(t, v.CanValidate("np.shopify.5"))
	assert.False(t, v.CanValidate("np.shopify.1"))
	assert.False(t, v.CanValidate("np.shopify.2"))
	assert.False(t, v.CanValidate("np.github.1"))
}

func TestShopifyValidator_ExtractDomain_FromBefore(t *testing.T) {
	v := NewShopifyValidator()

	match := &types.Match{
		RuleID: "np.shopify.3",
		NamedGroups: map[string][]byte{
			"token": []byte("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"),
		},
		Snippet: types.Snippet{
			Before:   []byte("shop = 'mystore.myshopify.com'"),
			Matching: []byte("token = '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'"),
			After:    []byte(""),
		},
	}

	domain := v.extractDomain(match)
	assert.Equal(t, "mystore.myshopify.com", domain)
}

func TestShopifyValidator_ExtractDomain_FromAfter(t *testing.T) {
	v := NewShopifyValidator()

	match := &types.Match{
		RuleID: "np.shopify.3",
		NamedGroups: map[string][]byte{
			"token": []byte("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"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# token config"),
			Matching: []byte("token = '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'"),
			After:    []byte("shop_url = 'cool-store.myshopify.com'"),
		},
	}

	domain := v.extractDomain(match)
	assert.Equal(t, "cool-store.myshopify.com", domain)
}

func TestShopifyValidator_ExtractDomain_FromMatching(t *testing.T) {
	v := NewShopifyValidator()

	match := &types.Match{
		RuleID: "np.shopify.4",
		NamedGroups: map[string][]byte{
			"token": []byte("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"),
		},
		Snippet: types.Snippet{
			Before:   []byte(""),
			Matching: []byte("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 handsomestranger.myshopify.com"),
			After:    []byte(""),
		},
	}

	domain := v.extractDomain(match)
	assert.Equal(t, "handsomestranger.myshopify.com", domain)
}

func TestShopifyValidator_ExtractDomain_WithHyphenatedName(t *testing.T) {
	v := NewShopifyValidator()

	match := &types.Match{
		RuleID: "np.shopify.5",
		NamedGroups: map[string][]byte{
			"token": []byte("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"),
		},
		Snippet: types.Snippet{
			Before:   []byte("SHOP_DOMAIN=my-cool-store.myshopify.com"),
			Matching: []byte("SHOP_PASSWORD=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"),
			After:    []byte(""),
		},
	}

	domain := v.extractDomain(match)
	assert.Equal(t, "my-cool-store.myshopify.com", domain)
}

func TestShopifyValidator_ExtractDomain_NotFound(t *testing.T) {
	v := NewShopifyValidator()

	match := &types.Match{
		RuleID: "np.shopify.3",
		NamedGroups: map[string][]byte{
			"token": []byte("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"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# no domain here"),
			Matching: []byte("token = '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'"),
			After:    []byte("# nothing here either"),
		},
	}

	domain := v.extractDomain(match)
	assert.Empty(t, domain)
}

func TestShopifyValidator_Validate_NoDomain(t *testing.T) {
	v := NewShopifyValidator()

	// Token present but no domain in context
	match := &types.Match{
		RuleID: "np.shopify.3",
		NamedGroups: map[string][]byte{
			"token": []byte("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"),
		},
		Snippet: types.Snippet{
			Before:   []byte("# no domain"),
			Matching: []byte("token = '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'"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "domain")
}

func TestShopifyValidator_Validate_NoNamedGroups(t *testing.T) {
	v := NewShopifyValidator()

	match := &types.Match{
		RuleID:      "np.shopify.3",
		NamedGroups: nil,
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "named capture groups")
}

func TestShopifyValidator_Validate_MissingToken(t *testing.T) {
	v := NewShopifyValidator()

	match := &types.Match{
		RuleID:      "np.shopify.3",
		NamedGroups: map[string][]byte{}, // No token
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
	assert.Contains(t, result.Message, "token")
}

func TestShopifyValidator_Validate_ValidToken(t *testing.T) {
	// Mock server returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify path and token header
		assert.Contains(t, r.URL.Path, "/admin/api/2024-01/shop.json")
		assert.NotEmpty(t, r.Header.Get("X-Shopify-Access-Token"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewShopifyValidatorWithClient(&http.Client{
		Transport: &shopifyMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.shopify.3",
		NamedGroups: map[string][]byte{
			"token": []byte("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"),
		},
		Snippet: types.Snippet{
			Before:   []byte("shop = 'mystore.myshopify.com'"),
			Matching: []byte("token = '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'"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusValid, result.Status)
	assert.Contains(t, result.Message, "mystore.myshopify.com")
}

func TestShopifyValidator_Validate_InvalidToken(t *testing.T) {
	// Mock server returns 401 Unauthorized
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	v := NewShopifyValidatorWithClient(&http.Client{
		Transport: &shopifyMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.shopify.4",
		NamedGroups: map[string][]byte{
			"token": []byte("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"),
		},
		Snippet: types.Snippet{
			Before:   []byte("shop = 'mystore.myshopify.com'"),
			Matching: []byte("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"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestShopifyValidator_Validate_ForbiddenToken(t *testing.T) {
	// Mock server returns 403 Forbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := NewShopifyValidatorWithClient(&http.Client{
		Transport: &shopifyMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.shopify.5",
		NamedGroups: map[string][]byte{
			"token": []byte("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"),
		},
		Snippet: types.Snippet{
			Before:   []byte("SHOP_DOMAIN=mystore.myshopify.com"),
			Matching: []byte("SHOP_PASSWORD=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"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusInvalid, result.Status)
}

func TestShopifyValidator_Validate_UnexpectedStatus(t *testing.T) {
	// Mock server returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := NewShopifyValidatorWithClient(&http.Client{
		Transport: &shopifyMockTransport{server: server},
	})

	match := &types.Match{
		RuleID: "np.shopify.3",
		NamedGroups: map[string][]byte{
			"token": []byte("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"),
		},
		Snippet: types.Snippet{
			Before:   []byte("shop = 'mystore.myshopify.com'"),
			Matching: []byte("token = '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'"),
			After:    []byte(""),
		},
	}

	result, err := v.Validate(context.Background(), match)
	assert.NoError(t, err)
	assert.Equal(t, types.StatusUndetermined, result.Status)
}

// shopifyMockTransport redirects requests to the mock server.
type shopifyMockTransport struct {
	server *httptest.Server
}

func (t *shopifyMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
