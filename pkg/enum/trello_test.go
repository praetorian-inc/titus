package enum

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testTrelloEnumerator(t *testing.T, handler http.Handler) *TrelloEnumerator {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	e, err := NewTrelloEnumerator(TrelloConfig{
		APIKey:    "test-key",
		Token:     "test-token",
		RateLimit: 100,
	})
	require.NoError(t, err)
	e.apiBase = srv.URL
	return e
}

func TestNewTrelloEnumerator(t *testing.T) {
	e, err := NewTrelloEnumerator(TrelloConfig{
		APIKey: "key",
		Token:  "tok",
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestNewTrelloEnumerator_MissingAPIKey(t *testing.T) {
	_, err := NewTrelloEnumerator(TrelloConfig{
		Token: "tok",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestNewTrelloEnumerator_MissingToken(t *testing.T) {
	_, err := NewTrelloEnumerator(TrelloConfig{
		APIKey: "key",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is required")
}

func TestNewTrelloEnumerator_DefaultRateLimit(t *testing.T) {
	e, err := NewTrelloEnumerator(TrelloConfig{
		APIKey: "key",
		Token:  "tok",
	})
	require.NoError(t, err)
	assert.Equal(t, 3.0, e.config.RateLimit)
}

func TestTrelloProvenance(t *testing.T) {
	prov := trelloProvenance("card", "card123", "My Card", "https://trello.com/c/card123")

	assert.Equal(t, "trello", prov.Payload["source"])
	assert.Equal(t, "card", prov.Payload["entityType"])
	assert.Equal(t, "card123", prov.Payload["identifier"])
	assert.Equal(t, "My Card", prov.Payload["title"])
	assert.Equal(t, "https://trello.com/c/card123", prov.Payload["url"])
}

func TestTrelloBuildCardBlob_Basic(t *testing.T) {
	card := trelloCard{
		ID:   "c1",
		Name: "Test Card",
		Desc: "A description",
		URL:  "https://trello.com/c/c1",
	}
	blob := trelloBuildCardBlob("My Board", card, nil, nil)
	s := string(blob)

	assert.Contains(t, s, "Board: My Board")
	assert.Contains(t, s, "Card: Test Card")
	assert.Contains(t, s, "URL: https://trello.com/c/c1")
	assert.Contains(t, s, "A description")
}

func TestTrelloBuildCardBlob_WithComments(t *testing.T) {
	card := trelloCard{ID: "c1", Name: "Card", Desc: "desc"}
	comments := []trelloAction{
		{ID: "a1", Data: struct {
			Text string `json:"text"`
		}{Text: "first comment"}},
		{ID: "a2", Data: struct {
			Text string `json:"text"`
		}{Text: "second comment"}},
	}
	blob := trelloBuildCardBlob("Board", card, comments, nil)
	s := string(blob)

	assert.Contains(t, s, "first comment")
	assert.Contains(t, s, "second comment")
	assert.Equal(t, 2, strings.Count(s, "--- Comment ---"))
}

func TestTrelloBuildCardBlob_WithChecklists(t *testing.T) {
	card := trelloCard{ID: "c1", Name: "Card", Desc: ""}
	checklists := []trelloChecklist{
		{
			ID:   "cl1",
			Name: "TODO",
			CheckItems: []trelloCheckItem{
				{ID: "ci1", Name: "Item A"},
				{ID: "ci2", Name: "Item B"},
			},
		},
	}
	blob := trelloBuildCardBlob("Board", card, nil, checklists)
	s := string(blob)

	assert.Contains(t, s, "--- Checklist: TODO ---")
	assert.Contains(t, s, "- Item A")
	assert.Contains(t, s, "- Item B")
}

func TestTrelloAuth_QueryParams(t *testing.T) {
	var gotKey, gotToken string
	e := testTrelloEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("key")
		gotToken = r.URL.Query().Get("token")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("[]"))
	}))

	_, _ = e.trelloGet(context.Background(), "/test")
	assert.Equal(t, "test-key", gotKey)
	assert.Equal(t, "test-token", gotToken)
}

func TestTrelloFetchBoards(t *testing.T) {
	boards := []trelloBoard{
		{ID: "b1", Name: "Board One", Desc: "desc1", URL: "https://trello.com/b/b1"},
		{ID: "b2", Name: "Board Two", Desc: "desc2", URL: "https://trello.com/b/b2"},
	}
	e := testTrelloEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/members/me/boards") {
			_ = json.NewEncoder(w).Encode(boards)
			return
		}
		w.WriteHeader(404)
	}))

	result, err := e.trelloFetchBoards(context.Background())
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "Board One", result[0].Name)
}

func TestTrelloFetchCards(t *testing.T) {
	cards := []trelloCard{
		{ID: "c1", Name: "Card A", Desc: "desc", URL: "https://trello.com/c/c1"},
	}
	e := testTrelloEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/boards/b1/cards") {
			_ = json.NewEncoder(w).Encode(cards)
			return
		}
		w.WriteHeader(404)
	}))

	result, err := e.trelloFetchCards(context.Background(), "b1")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "Card A", result[0].Name)
}

func TestTrelloFetchComments(t *testing.T) {
	actions := []trelloAction{
		{ID: "a1", Type: "commentCard", Data: struct {
			Text string `json:"text"`
		}{Text: "hello world"}},
	}
	e := testTrelloEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/cards/c1/actions") {
			_ = json.NewEncoder(w).Encode(actions)
			return
		}
		w.WriteHeader(404)
	}))

	result, err := e.trelloFetchComments(context.Background(), "c1")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "hello world", result[0].Data.Text)
}

func TestTrelloFetchChecklists(t *testing.T) {
	checklists := []trelloChecklist{
		{
			ID:   "cl1",
			Name: "My List",
			CheckItems: []trelloCheckItem{
				{ID: "ci1", Name: "Do thing"},
			},
		},
	}
	e := testTrelloEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/cards/c1/checklists") {
			_ = json.NewEncoder(w).Encode(checklists)
			return
		}
		w.WriteHeader(404)
	}))

	result, err := e.trelloFetchChecklists(context.Background(), "c1")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "My List", result[0].Name)
	assert.Len(t, result[0].CheckItems, 1)
}

func TestTrelloEnumerate_EndToEnd(t *testing.T) {
	boards := []trelloBoard{
		{ID: "b1", Name: "Board", URL: "https://trello.com/b/b1"},
	}
	cards := []trelloCard{
		{ID: "c1", Name: "Card One", Desc: "secret data", URL: "https://trello.com/c/c1"},
	}
	comments := []trelloAction{
		{ID: "a1", Data: struct {
			Text string `json:"text"`
		}{Text: "a comment"}},
	}
	checklists := []trelloChecklist{
		{ID: "cl1", Name: "Steps", CheckItems: []trelloCheckItem{
			{ID: "ci1", Name: "step 1"},
		}},
	}

	e := testTrelloEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/members/me/boards"):
			_ = json.NewEncoder(w).Encode(boards)
		case strings.Contains(r.URL.Path, "/boards/b1/cards"):
			_ = json.NewEncoder(w).Encode(cards)
		case strings.Contains(r.URL.Path, "/cards/c1/actions"):
			_ = json.NewEncoder(w).Encode(comments)
		case strings.Contains(r.URL.Path, "/cards/c1/checklists"):
			_ = json.NewEncoder(w).Encode(checklists)
		default:
			w.WriteHeader(404)
		}
	}))

	var blobs []string
	var provs []types.Provenance
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, string(content))
		provs = append(provs, prov)
		return nil
	})

	require.NoError(t, err)
	assert.Len(t, blobs, 1)
	assert.Contains(t, blobs[0], "secret data")
	assert.Contains(t, blobs[0], "a comment")
	assert.Contains(t, blobs[0], "step 1")

	ep := provs[0].(types.ExtendedProvenance)
	assert.Equal(t, "trello", ep.Payload["source"])
	assert.Equal(t, "card", ep.Payload["entityType"])
	assert.Equal(t, "c1", ep.Payload["identifier"])
}

func TestTrelloEnumerate_BoardFilter(t *testing.T) {
	boards := []trelloBoard{
		{ID: "b1", Name: "Include"},
		{ID: "b2", Name: "Exclude"},
	}

	e := testTrelloEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/members/me/boards"):
			_ = json.NewEncoder(w).Encode(boards)
		case strings.Contains(r.URL.Path, "/boards/b1/cards"):
			_ = json.NewEncoder(w).Encode([]trelloCard{{ID: "c1", Name: "Kept", URL: "u"}})
		case strings.Contains(r.URL.Path, "/cards/c1/actions"):
			_ = json.NewEncoder(w).Encode([]trelloAction{})
		case strings.Contains(r.URL.Path, "/cards/c1/checklists"):
			_ = json.NewEncoder(w).Encode([]trelloChecklist{})
		default:
			w.WriteHeader(404)
		}
	}))
	e.config.Boards = []string{"b1"}

	var count int
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestTrelloEnumerate_ErrorResilience(t *testing.T) {
	boards := []trelloBoard{
		{ID: "b1", Name: "Board"},
	}
	cards := []trelloCard{
		{ID: "c1", Name: "Card", Desc: "data", URL: "u"},
	}

	e := testTrelloEnumerator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/members/me/boards"):
			_ = json.NewEncoder(w).Encode(boards)
		case strings.Contains(r.URL.Path, "/boards/b1/cards"):
			_ = json.NewEncoder(w).Encode(cards)
		case strings.Contains(r.URL.Path, "/cards/c1/actions"):
			w.WriteHeader(403)
		case strings.Contains(r.URL.Path, "/cards/c1/checklists"):
			w.WriteHeader(403)
		default:
			w.WriteHeader(404)
		}
	}))

	var count int
	err := e.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		count++
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enumeration errors")
	assert.Equal(t, 1, count)
}
