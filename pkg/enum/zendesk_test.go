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

var _ Enumerator = (*ZendeskEnumerator)(nil)

func TestZendeskEnumerator_Construction(t *testing.T) {
	e, err := NewZendeskEnumerator(ZendeskConfig{
		Subdomain: "mycompany",
		Email:     "agent@example.com",
		Token:     "abc123",
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestZendeskEnumerator_RequiresSubdomain(t *testing.T) {
	_, err := NewZendeskEnumerator(ZendeskConfig{
		Email: "agent@example.com",
		Token: "abc123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "subdomain")
}

func TestZendeskEnumerator_RequiresEmail(t *testing.T) {
	_, err := NewZendeskEnumerator(ZendeskConfig{
		Subdomain: "mycompany",
		Token:     "abc123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email")
}

func TestZendeskEnumerator_RequiresToken(t *testing.T) {
	_, err := NewZendeskEnumerator(ZendeskConfig{
		Subdomain: "mycompany",
		Email:     "agent@example.com",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestZendeskEnumerator_DefaultRateLimit(t *testing.T) {
	e, err := NewZendeskEnumerator(ZendeskConfig{
		Subdomain: "mycompany",
		Email:     "agent@example.com",
		Token:     "abc123",
	})
	require.NoError(t, err)
	assert.Equal(t, 3.0, e.config.RateLimit)
}

func TestZendeskProvenance(t *testing.T) {
	prov := zdProvenance("ticket", "12345", "Server down", "https://mycompany.zendesk.com/agent/tickets/12345")
	assert.Equal(t, "extended", prov.Kind())
	assert.Equal(t, "zendesk", prov.Payload["source"])
	assert.Equal(t, "ticket", prov.Payload["entityType"])
	assert.Equal(t, "12345", prov.Payload["identifier"])
	assert.Equal(t, "Server down", prov.Payload["title"])
}

func TestZendeskBuildTicketBlob(t *testing.T) {
	ticket := zdTicket{
		ID:          12345,
		Subject:     "Leaked API key",
		Description: "Found key: sk-abc123 in production config",
	}
	comments := []zdComment{
		{ID: 1, PlainBody: "Rotated the key", Public: true},
		{ID: 2, Body: "Internal: old key was AKIA1234", Public: false},
	}
	blob := zdBuildTicketBlob(ticket, comments, "mycompany")
	content := string(blob)

	assert.Contains(t, content, "Type: ticket")
	assert.Contains(t, content, "ID: 12345")
	assert.Contains(t, content, "Subject: Leaked API key")
	assert.Contains(t, content, "sk-abc123")
	assert.Contains(t, content, "--- Comment (public) ---")
	assert.Contains(t, content, "Rotated the key")
	assert.Contains(t, content, "--- Comment (internal) ---")
	assert.Contains(t, content, "AKIA1234")
	assert.Contains(t, content, "mycompany.zendesk.com/agent/tickets/12345")
}

func TestZendeskBuildTicketBlob_NoComments(t *testing.T) {
	ticket := zdTicket{
		ID:          99,
		Subject:     "Empty ticket",
		Description: "Just a description",
	}
	blob := zdBuildTicketBlob(ticket, nil, "test")
	content := string(blob)

	assert.Contains(t, content, "Just a description")
	assert.NotContains(t, content, "--- Comment")
}

func TestZendeskBuildArticleBlob(t *testing.T) {
	article := zdArticle{
		ID:    555,
		Title: "Setup guide",
		Body:  "Set DB_PASSWORD=s3cret in .env",
		URL:   "https://mycompany.zendesk.com/hc/articles/555",
	}
	blob := zdBuildArticleBlob(article)
	content := string(blob)

	assert.Contains(t, content, "Type: article")
	assert.Contains(t, content, "ID: 555")
	assert.Contains(t, content, "Title: Setup guide")
	assert.Contains(t, content, "DB_PASSWORD=s3cret")
}

func testZendeskEnumerator(t *testing.T, serverURL string) *ZendeskEnumerator {
	t.Helper()
	e, err := NewZendeskEnumerator(ZendeskConfig{
		Subdomain: "test",
		Email:     "agent@example.com",
		Token:     "testtoken",
		RateLimit: 1000,
	})
	require.NoError(t, err)
	e.apiBase = serverURL
	return e
}

func TestZendeskAPI_Auth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok, "expected Basic auth")
		assert.Equal(t, "agent@example.com/token", user)
		assert.Equal(t, "testtoken", pass)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tickets":   []interface{}{},
			"next_page": nil,
		})
	}))
	defer server.Close()

	e := testZendeskEnumerator(t, server.URL)
	_, err := e.zdFetchTickets(context.Background())
	require.NoError(t, err)
}

func TestZendeskAPI_FetchTickets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tickets": []map[string]interface{}{
				{"id": 1, "subject": "Test ticket", "description": "password: hunter2"},
				{"id": 2, "subject": "Another ticket", "description": "API_KEY=sk-abc"},
			},
			"next_page": nil,
		})
	}))
	defer server.Close()

	e := testZendeskEnumerator(t, server.URL)
	tickets, err := e.zdFetchTickets(context.Background())
	require.NoError(t, err)
	assert.Len(t, tickets, 2)
	assert.Equal(t, "Test ticket", tickets[0].Subject)
	assert.Contains(t, tickets[1].Description, "sk-abc")
}

func TestZendeskAPI_Pagination(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")

		if callCount == 1 {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"tickets": []map[string]interface{}{
					{"id": 1, "subject": "Page 1"},
				},
				"next_page": fmt.Sprintf("http://%s/api/v2/tickets.json?page=2", r.Host),
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"tickets": []map[string]interface{}{
					{"id": 2, "subject": "Page 2"},
				},
				"next_page": nil,
			})
		}
	}))
	defer server.Close()

	e := testZendeskEnumerator(t, server.URL)
	tickets, err := e.zdFetchTickets(context.Background())
	require.NoError(t, err)
	assert.Len(t, tickets, 2)
	assert.Equal(t, 2, callCount)
}

func TestZendeskAPI_FetchComments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/tickets/42/comments")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"comments": []map[string]interface{}{
				{"id": 1, "plain_body": "Here is the API key: AKIA1234", "public": true},
				{"id": 2, "body": "Internal note with password", "public": false},
			},
			"next_page": nil,
		})
	}))
	defer server.Close()

	e := testZendeskEnumerator(t, server.URL)
	comments, err := e.zdFetchComments(context.Background(), 42)
	require.NoError(t, err)
	assert.Len(t, comments, 2)
	assert.Contains(t, comments[0].PlainBody, "AKIA1234")
	assert.False(t, comments[1].Public)
}

func TestZendeskAPI_FetchArticles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/help_center/articles")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"articles": []map[string]interface{}{
				{"id": 100, "title": "Setup guide", "body": "Set DB_PASSWORD=s3cret", "html_url": "https://test.zendesk.com/hc/articles/100"},
			},
			"next_page": nil,
		})
	}))
	defer server.Close()

	e := testZendeskEnumerator(t, server.URL)
	articles, err := e.zdFetchArticles(context.Background())
	require.NoError(t, err)
	assert.Len(t, articles, 1)
	assert.Equal(t, "Setup guide", articles[0].Title)
}

func TestZendeskEnumerate_EndToEnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(r.URL.Path, "/tickets/1/comments"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"comments": []map[string]interface{}{
					{"id": 10, "plain_body": "Rotated credential", "public": true},
				},
				"next_page": nil,
			})
		case strings.Contains(r.URL.Path, "/tickets"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"tickets": []map[string]interface{}{
					{"id": 1, "subject": "Leaked key", "description": "Found AKIA1234567890 in config"},
				},
				"next_page": nil,
			})
		case strings.Contains(r.URL.Path, "/help_center/articles"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"articles": []map[string]interface{}{
					{"id": 200, "title": "Deploy guide", "body": "export SECRET_KEY=hunter2", "html_url": "https://test.zendesk.com/hc/articles/200"},
				},
				"next_page": nil,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	e := testZendeskEnumerator(t, server.URL)

	var blobs []string
	var provs []types.Provenance
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		provs = append(provs, prov)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, blobs, 2)

	assert.Contains(t, blobs[0], "AKIA1234567890")
	assert.Contains(t, blobs[0], "Rotated credential")
	assert.Contains(t, blobs[0], "Type: ticket")

	assert.Contains(t, blobs[1], "SECRET_KEY=hunter2")
	assert.Contains(t, blobs[1], "Type: article")

	ep0 := provs[0].(types.ExtendedProvenance)
	assert.Equal(t, "zendesk", ep0.Payload["source"])
	assert.Equal(t, "ticket", ep0.Payload["entityType"])

	ep1 := provs[1].(types.ExtendedProvenance)
	assert.Equal(t, "article", ep1.Payload["entityType"])
}

func TestZendeskEnumerate_TicketError_ContinuesWithArticles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/tickets") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"articles": []map[string]interface{}{
				{"id": 1, "title": "Article", "body": "some content"},
			},
			"next_page": nil,
		})
	}))
	defer server.Close()

	e := testZendeskEnumerator(t, server.URL)

	var blobCount int
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobCount++
		return nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tickets")
	assert.Equal(t, 1, blobCount, "should still yield articles despite ticket failure")
}
