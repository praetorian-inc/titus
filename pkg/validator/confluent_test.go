// pkg/validator/confluent_test.go
package validator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfluentValidator_Name verifies the validator identifies itself as "confluent".
func TestConfluentValidator_Name(t *testing.T) {
	v := NewConfluentValidator()
	assert.Equal(t, "confluent", v.Name())
}

// TestConfluentValidator_CanValidate verifies that the validator accepts exactly the
// three confluent rule IDs and rejects unrelated ones.
func TestConfluentValidator_CanValidate(t *testing.T) {
	v := NewConfluentValidator()

	tests := []struct {
		ruleID string
		want   bool
	}{
		{"kingfisher.confluent.1", true},
		{"kingfisher.confluent.2", true},
		{"kingfisher.confluent.3", true},
		{"np.aws.1", false},
		{"np.github.3", false},
		{"titus.wandb.1", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.ruleID, func(t *testing.T) {
			assert.Equal(t, tc.want, v.CanValidate(tc.ruleID),
				"CanValidate(%q) should be %v", tc.ruleID, tc.want)
		})
	}
}

// TestConfluentValidator_ExtractCredentials verifies credential extraction for all
// match shapes produced by the three confluent rules.
func TestConfluentValidator_ExtractCredentials(t *testing.T) {
	const (
		validSecret64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01" // 64 chars
		validCflt     = "cfltqPLd2lLPAtWtHGNhN32WlZxoEj30pcg8mzaPlPJ937JlMa7n9YCRLooqgifw"
		validClientID = "ABCD1234EFGH5678" // 16 uppercase alphanumeric
	)

	snippetWithClientID := []byte(fmt.Sprintf("confluent api_key=%s\n", validClientID))

	tests := []struct {
		name       string
		match      *types.Match
		wantClient string
		wantSecret string
		wantErr    bool
	}{
		{
			name: "confluent.2: secret from NamedGroups, client_id from snippet Before",
			match: &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet:     types.Snippet{Before: snippetWithClientID},
			},
			wantClient: validClientID,
			wantSecret: validSecret64,
		},
		{
			name: "confluent.3: secret from Groups[0] (cflt token), client_id from snippet",
			match: &types.Match{
				RuleID:      "kingfisher.confluent.3",
				Groups:      [][]byte{[]byte(validCflt)},
				NamedGroups: map[string][]byte{},
				Snippet:     types.Snippet{Before: snippetWithClientID},
			},
			wantClient: validClientID,
			wantSecret: validCflt,
		},
		{
			name: "confluent.2: secret present but no client_id in snippet",
			match: &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet:     types.Snippet{Before: []byte("some unrelated context")},
			},
			wantErr: true,
		},
		{
			name: "confluent.1: client_id only, no secret",
			match: &types.Match{
				RuleID:      "kingfisher.confluent.1",
				NamedGroups: map[string][]byte{"client_id": []byte(validClientID)},
				Snippet:     types.Snippet{},
			},
			wantErr: true,
		},
		{
			name: "nil NamedGroups, no Groups",
			match: &types.Match{
				RuleID:  "kingfisher.confluent.2",
				Snippet: types.Snippet{Before: snippetWithClientID},
			},
			wantErr: true,
		},
		{
			name: "client_id from snippet Matching field",
			match: &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet: types.Snippet{
					Matching: []byte(fmt.Sprintf("kafka api_key=%s some text", validClientID)),
				},
			},
			wantClient: validClientID,
			wantSecret: validSecret64,
		},
		{
			name: "client_id from snippet After field",
			match: &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet: types.Snippet{
					After: []byte(fmt.Sprintf("confluent client_id=%s more", validClientID)),
				},
			},
			wantClient: validClientID,
			wantSecret: validSecret64,
		},
		{
			// Regression: api_key=<64-char-base64-secret> must NOT mis-grab the
			// first 16 chars of the secret as the client_id. The 16-char match is
			// not a word boundary (more [A-Z0-9] chars follow), so \b prevents it.
			// Extraction must return an error (no real 16-char client_id present).
			name: "64-char secret after api_key= is not mis-extracted as client_id",
			match: &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet: types.Snippet{
					Before: []byte("api_key=" + validSecret64),
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := NewConfluentValidator()
			clientID, secret, err := v.extractCredentials(tc.match)
			if tc.wantErr {
				require.Error(t, err, "expected error for match shape")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantClient, clientID, "client ID mismatch")
			assert.Equal(t, tc.wantSecret, secret, "secret mismatch")
		})
	}
}

// TestConfluentValidator_Validate verifies HTTP status to ValidationStatus mapping.
func TestConfluentValidator_Validate(t *testing.T) {
	const (
		validSecret64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01"
		validClientID = "ABCD1234EFGH5678"
	)
	snippetWithClientID := []byte(fmt.Sprintf("confluent api_key=%s\n", validClientID))

	tests := []struct {
		name       string
		httpStatus int
		match      *types.Match
		wantStatus types.ValidationStatus
	}{
		{
			name:       "HTTP 200 maps to StatusValid",
			httpStatus: http.StatusOK,
			match: &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet:     types.Snippet{Before: snippetWithClientID},
			},
			wantStatus: types.StatusValid,
		},
		{
			name:       "HTTP 401 maps to StatusInvalid",
			httpStatus: http.StatusUnauthorized,
			match: &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet:     types.Snippet{Before: snippetWithClientID},
			},
			wantStatus: types.StatusInvalid,
		},
		{
			// 403 = authenticated but not authorized for the resource.
			// The key is live; the caller may lack cloud-global API permissions.
			name:       "HTTP 403 maps to StatusValid (authenticated, key is live)",
			httpStatus: http.StatusForbidden,
			match: &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet:     types.Snippet{Before: snippetWithClientID},
			},
			wantStatus: types.StatusValid,
		},
		{
			name:       "HTTP 500 maps to StatusUndetermined",
			httpStatus: http.StatusInternalServerError,
			match: &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet:     types.Snippet{Before: snippetWithClientID},
			},
			wantStatus: types.StatusUndetermined,
		},
		{
			name:       "missing client_id maps to StatusUndetermined without HTTP request",
			httpStatus: http.StatusOK,
			match: &types.Match{
				RuleID:      "kingfisher.confluent.1",
				NamedGroups: map[string][]byte{"client_id": []byte(validClientID)},
				Snippet:     types.Snippet{},
			},
			wantStatus: types.StatusUndetermined,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.httpStatus)
			}))
			defer ts.Close()

			v := NewConfluentValidatorWithClient(ts.Client())
			v.baseURL = ts.URL

			result, err := v.Validate(context.Background(), tc.match)
			require.NoError(t, err, "Validate must never return a non-nil error")
			assert.Equal(t, tc.wantStatus, result.Status)
		})
	}
}

// TestConfluentValidator_ExtractClusterContext verifies extraction of cluster
// endpoint and lkc-id from snippet context.
func TestConfluentValidator_ExtractClusterContext(t *testing.T) {
	const (
		realEndpoint = "https://pkc-419q3.us-east4.gcp.confluent.cloud:443"
		realLKC      = "lkc-nvodzyv"
	)

	tests := []struct {
		name         string
		snippet      types.Snippet
		wantEndpoint string
		wantLKC      string
	}{
		{
			name: "endpoint and lkc in Before",
			snippet: types.Snippet{
				Before: []byte("bootstrap=" + realEndpoint + " cluster=" + realLKC),
			},
			wantEndpoint: realEndpoint,
			wantLKC:      realLKC,
		},
		{
			name: "endpoint in Before, lkc in After",
			snippet: types.Snippet{
				Before: []byte("bootstrap=" + realEndpoint),
				After:  []byte("cluster=" + realLKC),
			},
			wantEndpoint: realEndpoint,
			wantLKC:      realLKC,
		},
		{
			name: "no cluster context -> both empty (falls back to cloud path)",
			snippet: types.Snippet{
				Before: []byte("confluent api_key=ABCD1234EFGH5678"),
			},
			wantEndpoint: "",
			wantLKC:      "",
		},
		{
			name: "endpoint without port",
			snippet: types.Snippet{
				Before: []byte("host=https://pkc-xyz99.eu-west1.gcp.confluent.cloud cluster=" + realLKC),
			},
			wantEndpoint: "https://pkc-xyz99.eu-west1.gcp.confluent.cloud",
			wantLKC:      realLKC,
		},
		{
			name: "endpoint only, no lkc -> no cluster path",
			snippet: types.Snippet{
				Before: []byte("bootstrap=" + realEndpoint),
			},
			wantEndpoint: realEndpoint,
			wantLKC:      "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := NewConfluentValidator()
			ep, lkc := v.extractClusterContext(&types.Match{Snippet: tc.snippet})
			assert.Equal(t, tc.wantEndpoint, ep)
			assert.Equal(t, tc.wantLKC, lkc)
		})
	}
}

// TestConfluentValidator_ClusterPath verifies that when BOTH a cluster endpoint
// and lkc-id are found in the snippet, Validate uses the cluster-specific URL
// and maps responses correctly (200=Valid, 403=Valid, 401=Invalid, 5xx=Undetermined).
func TestConfluentValidator_ClusterPath(t *testing.T) {
	const (
		validSecret64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01"
		validClientID = "ABCD1234EFGH5678"
		clusterLKC    = "lkc-nvodzyv"
	)

	tests := []struct {
		name           string
		httpStatus     int
		wantStatus     types.ValidationStatus
		wantPathPrefix string // expected URL path prefix
	}{
		{
			name:           "cluster 200 -> StatusValid",
			httpStatus:     http.StatusOK,
			wantStatus:     types.StatusValid,
			wantPathPrefix: "/kafka/v3/clusters/" + clusterLKC + "/topics",
		},
		{
			// 403 = authenticated but the cluster key lacks topic-list permission.
			// The key is live; mark Valid.
			name:           "cluster 403 -> StatusValid (key authenticated, insufficient permissions)",
			httpStatus:     http.StatusForbidden,
			wantStatus:     types.StatusValid,
			wantPathPrefix: "/kafka/v3/clusters/" + clusterLKC + "/topics",
		},
		{
			name:           "cluster 401 -> StatusInvalid",
			httpStatus:     http.StatusUnauthorized,
			wantStatus:     types.StatusInvalid,
			wantPathPrefix: "/kafka/v3/clusters/" + clusterLKC + "/topics",
		},
		{
			name:           "cluster 500 -> StatusUndetermined",
			httpStatus:     http.StatusInternalServerError,
			wantStatus:     types.StatusUndetermined,
			wantPathPrefix: "/kafka/v3/clusters/" + clusterLKC + "/topics",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(tc.httpStatus)
			}))
			defer ts.Close()

			// Put a realistic confluent cluster endpoint in the snippet so
			// extractClusterContext succeeds (matches pkc-...confluent.cloud regex).
			// The actual HTTP request is redirected to the httptest server via
			// the clusterBaseURL test override.
			const fakeEndpoint = "https://pkc-419q3.us-east4.gcp.confluent.cloud:443"
			snippetContext := []byte("bootstrap=" + fakeEndpoint + " cluster=" + clusterLKC)
			match := &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet: types.Snippet{
					Before: snippetContext,
					After:  []byte("api_key=" + validClientID),
				},
			}

			v := NewConfluentValidatorWithClient(ts.Client())
			v.baseURL = ts.URL        // cloud fallback (not used in this test)
			v.clusterBaseURL = ts.URL // redirect cluster requests to httptest server

			result, err := v.Validate(context.Background(), match)
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, result.Status)
			assert.Equal(t, tc.wantPathPrefix, gotPath, "request must hit cluster topic-list endpoint")
		})
	}
}

// TestConfluentValidator_CloudFallback verifies that when cluster context is
// absent (no pkc endpoint or no lkc-id), Validate falls back to the cloud/global
// key path and does NOT return an error.
func TestConfluentValidator_CloudFallback(t *testing.T) {
	const (
		validSecret64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01"
		validClientID = "ABCD1234EFGH5678"
	)
	snippetWithClientID := []byte(fmt.Sprintf("confluent api_key=%s\n", validClientID))

	tests := []struct {
		name    string
		snippet types.Snippet
	}{
		{
			name:    "no cluster context at all",
			snippet: types.Snippet{Before: snippetWithClientID},
		},
		{
			name: "endpoint without lkc -> fallback",
			snippet: types.Snippet{
				Before: append(snippetWithClientID, []byte(" bootstrap=https://pkc-xyz.confluent.cloud:443")...),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			}))
			defer ts.Close()

			v := NewConfluentValidatorWithClient(ts.Client())
			v.baseURL = ts.URL

			match := &types.Match{
				RuleID:      "kingfisher.confluent.2",
				NamedGroups: map[string][]byte{"secret": []byte(validSecret64)},
				Snippet:     tc.snippet,
			}
			result, err := v.Validate(context.Background(), match)
			require.NoError(t, err)
			assert.Equal(t, types.StatusValid, result.Status)
			assert.Equal(t, "/iam/v2/api-keys", gotPath, "fallback must hit cloud IAM endpoint")
		})
	}
}
