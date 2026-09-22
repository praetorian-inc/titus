package enum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ Enumerator = (*ServiceNowEnumerator)(nil)

func TestServiceNowEnumerator_Construction(t *testing.T) {
	e, err := NewServiceNowEnumerator(ServiceNowConfig{
		Instance: "https://mycompany.service-now.com",
		Username: "admin",
		Password: "secret",
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestServiceNowEnumerator_RequiresInstance(t *testing.T) {
	_, err := NewServiceNowEnumerator(ServiceNowConfig{
		Username: "admin",
		Password: "secret",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "instance")
}

func TestServiceNowEnumerator_RequiresAuth(t *testing.T) {
	_, err := NewServiceNowEnumerator(ServiceNowConfig{
		Instance: "https://mycompany.service-now.com",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth")
}

func TestServiceNowEnumerator_AcceptsOAuthToken(t *testing.T) {
	e, err := NewServiceNowEnumerator(ServiceNowConfig{
		Instance:   "https://mycompany.service-now.com",
		OAuthToken: "bearer-token-here",
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestServiceNowEnumerator_RejectsInsecureHTTP(t *testing.T) {
	_, err := NewServiceNowEnumerator(ServiceNowConfig{
		Instance: "http://mycompany.service-now.com",
		Username: "admin",
		Password: "secret",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "plaintext HTTP")
}

func TestServiceNowEnumerator_AllowsInsecureHTTP(t *testing.T) {
	e, err := NewServiceNowEnumerator(ServiceNowConfig{
		Instance:          "http://mycompany.service-now.com",
		Username:          "admin",
		Password:          "secret",
		AllowInsecureHTTP: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestServiceNowEnumerator_DefaultTables(t *testing.T) {
	e, err := NewServiceNowEnumerator(ServiceNowConfig{
		Instance: "https://mycompany.service-now.com",
		Username: "admin",
		Password: "secret",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"incident", "change_request", "kb_knowledge"}, e.config.Tables)
}

func TestServiceNowEnumerator_CustomTables(t *testing.T) {
	e, err := NewServiceNowEnumerator(ServiceNowConfig{
		Instance: "https://mycompany.service-now.com",
		Username: "admin",
		Password: "secret",
		Tables:   []string{"cmdb_ci", "sc_req_item"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"cmdb_ci", "sc_req_item"}, e.config.Tables)
}

func TestServiceNowEnumerator_DefaultRateLimit(t *testing.T) {
	e, err := NewServiceNowEnumerator(ServiceNowConfig{
		Instance: "https://mycompany.service-now.com",
		Username: "admin",
		Password: "secret",
	})
	require.NoError(t, err)
	assert.Equal(t, 3.0, e.config.RateLimit)
}

func TestServiceNowProvenance(t *testing.T) {
	prov := snProvenance("incident", "abc123", "INC0010001", "Server down", "https://mycompany.service-now.com/incident.do?sys_id=abc123")
	assert.Equal(t, "extended", prov.Kind())
	assert.Equal(t, "servicenow", prov.Payload["source"])
	assert.Equal(t, "incident", prov.Payload["entityType"])
	assert.Equal(t, "abc123", prov.Payload["identifier"])
	assert.Equal(t, "INC0010001", prov.Payload["number"])
	assert.Equal(t, "Server down", prov.Payload["title"])
}

func TestServiceNowBuildRecordBlob(t *testing.T) {
	rec := snRecord{
		SysID:            "abc123",
		Number:           "INC0010001",
		ShortDescription: "DB password exposed",
		Description:      "Found password: hunter2 in config file",
		WorkNotes:        "Rotated credential",
		Comments:         "Customer confirmed rotation",
	}
	blob := snBuildRecordBlob("incident", rec, "https://mycompany.service-now.com")
	content := string(blob)

	assert.Contains(t, content, "Table: incident")
	assert.Contains(t, content, "Number: INC0010001")
	assert.Contains(t, content, "Short Description: DB password exposed")
	assert.Contains(t, content, "hunter2")
	assert.Contains(t, content, "--- Work Notes ---")
	assert.Contains(t, content, "Rotated credential")
	assert.Contains(t, content, "--- Comments ---")
	assert.Contains(t, content, "Customer confirmed rotation")
	assert.Contains(t, content, "incident.do?sys_id=abc123")
}

func TestServiceNowBuildRecordBlob_KBArticle(t *testing.T) {
	rec := snRecord{
		SysID:            "kb001",
		Number:           "KB0010001",
		ShortDescription: "SSH key setup",
		Text:             "Use ssh-keygen to generate keys. Example key: AKIA...",
	}
	blob := snBuildRecordBlob("kb_knowledge", rec, "https://mycompany.service-now.com")
	content := string(blob)

	assert.Contains(t, content, "Table: kb_knowledge")
	assert.Contains(t, content, "AKIA...")
	assert.NotContains(t, content, "--- Work Notes ---")
	assert.NotContains(t, content, "--- Comments ---")
}

func testServiceNowEnumerator(t *testing.T, serverURL string, tables []string) *ServiceNowEnumerator {
	t.Helper()
	if tables == nil {
		tables = snDefaultTables
	}
	e, err := NewServiceNowEnumerator(ServiceNowConfig{
		Instance: "https://mycompany.service-now.com",
		Username: "admin",
		Password: "secret",
		Tables:   tables,
		RateLimit: 1000,
	})
	require.NoError(t, err)
	e.apiBase = serverURL
	return e
}

func TestServiceNowAPI_BasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok, "expected Basic auth")
		assert.Equal(t, "admin", user)
		assert.Equal(t, "secret", pass)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": []interface{}{},
		})
	}))
	defer server.Close()

	e := testServiceNowEnumerator(t, server.URL, []string{"incident"})
	_, err := e.snFetchRecords(context.Background(), "incident")
	require.NoError(t, err)
}

func TestServiceNowAPI_BearerAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer my-oauth-token", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": []interface{}{},
		})
	}))
	defer server.Close()

	e, err := NewServiceNowEnumerator(ServiceNowConfig{
		Instance:   "https://mycompany.service-now.com",
		OAuthToken: "my-oauth-token",
		Tables:     []string{"incident"},
		RateLimit:  1000,
	})
	require.NoError(t, err)
	e.apiBase = server.URL

	_, err = e.snFetchRecords(context.Background(), "incident")
	require.NoError(t, err)
}

func TestServiceNowAPI_FetchRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/incident")
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": []map[string]interface{}{
				{
					"sys_id":            "id1",
					"number":            "INC0010001",
					"short_description": "Test incident",
					"description":       "Description with API_KEY=sk-abc123",
					"work_notes":        "",
					"comments":          "",
				},
				{
					"sys_id":            "id2",
					"number":            "INC0010002",
					"short_description": "Another incident",
					"description":       "Password: hunter2",
					"work_notes":        "Rotated cred",
					"comments":          "User notified",
				},
			},
		})
	}))
	defer server.Close()

	e := testServiceNowEnumerator(t, server.URL, []string{"incident"})
	records, err := e.snFetchRecords(context.Background(), "incident")
	require.NoError(t, err)
	assert.Len(t, records, 2)
	assert.Equal(t, "INC0010001", records[0].Number)
	assert.Contains(t, records[1].Description, "hunter2")
}

func TestServiceNowAPI_Pagination(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		offset := r.URL.Query().Get("sysparm_offset")

		var records []map[string]interface{}
		if offset == "0" || offset == "" {
			for i := 0; i < 100; i++ {
				records = append(records, map[string]interface{}{
					"sys_id": fmt.Sprintf("page1-%d", i),
					"number": fmt.Sprintf("INC%07d", i),
				})
			}
		} else {
			records = append(records, map[string]interface{}{
				"sys_id": "page2-0",
				"number": "INC0000100",
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": records,
		})
	}))
	defer server.Close()

	e := testServiceNowEnumerator(t, server.URL, []string{"incident"})
	records, err := e.snFetchRecords(context.Background(), "incident")
	require.NoError(t, err)
	assert.Len(t, records, 101)
	assert.Equal(t, 2, callCount, "should paginate with two requests")
}

func TestServiceNowEnumerate_EndToEnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "/incident") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": []map[string]interface{}{
					{
						"sys_id":            "inc1",
						"number":            "INC0010001",
						"short_description": "Leaked key",
						"description":       "Found AKIA1234567890EXAMPLE in config",
					},
				},
			})
		} else if strings.Contains(r.URL.Path, "/kb_knowledge") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": []map[string]interface{}{
					{
						"sys_id":            "kb1",
						"number":            "KB0010001",
						"short_description": "Setup guide",
						"text":              "Set DB_PASSWORD=s3cret in .env",
					},
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"result": []interface{}{},
			})
		}
	}))
	defer server.Close()

	e := testServiceNowEnumerator(t, server.URL, []string{"incident", "kb_knowledge"})

	var blobs []string
	var provs []types.Provenance
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		provs = append(provs, prov)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, blobs, 2)

	assert.Contains(t, blobs[0], "AKIA1234567890EXAMPLE")
	assert.Contains(t, blobs[0], "Table: incident")

	assert.Contains(t, blobs[1], "DB_PASSWORD=s3cret")
	assert.Contains(t, blobs[1], "Table: kb_knowledge")

	ep0 := provs[0].(types.ExtendedProvenance)
	assert.Equal(t, "servicenow", ep0.Payload["source"])
	assert.Equal(t, "incident", ep0.Payload["entityType"])
}

func TestServiceNowEnumerate_TableError_ContinuesOtherTables(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/incident") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": []map[string]interface{}{
				{"sys_id": "kb1", "number": "KB001", "text": "some content"},
			},
		})
	}))
	defer server.Close()

	e := testServiceNowEnumerator(t, server.URL, []string{"incident", "kb_knowledge"})

	var blobCount int
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobCount++
		return nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "table incident")
	assert.Equal(t, 1, blobCount, "should still yield kb_knowledge records despite incident failure")
}
