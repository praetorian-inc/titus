package enum

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAsanaEnumerator_RequiresToken(t *testing.T) {
	_, err := NewAsanaEnumerator(AsanaConfig{
		Workspace: "W1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestAsanaEnumerator_NoScopeAllowed(t *testing.T) {
	// Empty scope is now valid; no scope means "all workspaces visible to token".
	e, err := NewAsanaEnumerator(AsanaConfig{
		Token: "test-token",
	})
	require.NoError(t, err)
	require.NotNil(t, e)
}

func TestAsanaEnumerator_ValidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  AsanaConfig
	}{
		{name: "workspace only", cfg: AsanaConfig{Token: "tok", Workspace: "W1"}},
		{name: "team only", cfg: AsanaConfig{Token: "tok", Team: "T1"}},
		{name: "project only", cfg: AsanaConfig{Token: "tok", Project: "P1"}},
		{name: "with attachments", cfg: AsanaConfig{Token: "tok", Workspace: "W1", IncludeAttachments: true}},
		{name: "custom rate", cfg: AsanaConfig{Token: "tok", Workspace: "W1", RatePerSec: 10}},
		{name: "no scope", cfg: AsanaConfig{Token: "tok"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewAsanaEnumerator(tt.cfg)
			require.NoError(t, err)
			require.NotNil(t, e)
		})
	}
}

func asanaResponse(data interface{}) []byte {
	type env struct {
		Data interface{} `json:"data"`
	}
	b, _ := json.Marshal(env{Data: data})
	return b
}

func asanaListResponse(data interface{}, nextOffset string) []byte {
	type nextPage struct {
		Offset string `json:"offset"`
	}
	type env struct {
		Data     interface{} `json:"data"`
		NextPage *nextPage   `json:"next_page"`
	}
	e := env{Data: data}
	if nextOffset != "" {
		e.NextPage = &nextPage{Offset: nextOffset}
	}
	b, _ := json.Marshal(e)
	return b
}

func TestAsanaEnumerator_EndToEnd(t *testing.T) {
	storiesCallCount := 0
	mp4DownloadCalled := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		offset := r.URL.Query().Get("offset")

		switch {
		case path == "/workspaces/W1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(asanaResponse(map[string]string{"gid": "W1", "name": "Acme"}))

		case path == "/workspaces/W1/teams":
			w.Header().Set("Content-Type", "application/json")
			teams := []map[string]string{{"gid": "TM1", "name": "Engineering", "description": "Engineers team"}}
			_, _ = w.Write(asanaListResponse(teams, ""))

		case r.URL.Path == "/goals" && r.URL.Query().Get("workspace") == "W1":
			w.Header().Set("Content-Type", "application/json")
			goals := []map[string]string{
				{"gid": "G1", "name": "Grow Revenue", "notes": "goal notes here", "permalink_url": "https://app.asana.com/G1"},
			}
			_, _ = w.Write(asanaListResponse(goals, ""))

		case path == "/workspaces/W1/projects" && offset == "":
			w.Header().Set("Content-Type", "application/json")
			projects := []map[string]interface{}{
				{
					"gid": "P1", "name": "Project Alpha", "notes": "Alpha notes",
					"permalink_url": "https://app.asana.com/P1",
					"brief":         map[string]string{"gid": "B1"},
				},
			}
			_, _ = w.Write(asanaListResponse(projects, "page2"))

		case path == "/workspaces/W1/projects" && offset == "page2":
			w.Header().Set("Content-Type", "application/json")
			projects := []map[string]string{{"gid": "P2", "name": "Project Beta", "notes": "", "permalink_url": "https://app.asana.com/P2"}}
			_, _ = w.Write(asanaListResponse(projects, ""))

		case path == "/project_briefs/B1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(asanaResponse(map[string]string{
				"gid":  "B1",
				"text": "Alpha brief rich text",
			}))

		case path == "/projects/P1/project_statuses":
			w.Header().Set("Content-Type", "application/json")
			statuses := []map[string]string{{"gid": "PS1", "title": "On Track", "text": "Everything is going well"}}
			_, _ = w.Write(asanaListResponse(statuses, ""))

		case path == "/task_templates" && r.URL.Query().Get("project") == "P1":
			w.Header().Set("Content-Type", "application/json")
			templates := []map[string]string{
				{"gid": "TT1", "name": "Bug Report Template"},
			}
			_, _ = w.Write(asanaListResponse(templates, ""))

		case path == "/task_templates" && r.URL.Query().Get("project") == "P2":
			// Free tier - no templates
			http.NotFound(w, r)

		case path == "/projects/P1/tasks":
			w.Header().Set("Content-Type", "application/json")
			tasks := []map[string]interface{}{
				{
					"gid": "T1", "name": "Task One", "notes": "task notes here",
					"permalink_url": "https://app.asana.com/T1",
					"custom_fields": []map[string]string{
						{"gid": "CF1", "name": "Connection String", "type": "text", "text_value": "postgres://user:pass@host/db"},
						{"gid": "CF2", "name": "Priority", "type": "enum", "text_value": ""},
					},
					"external": map[string]string{"data": "secret-external-blob"},
				},
			}
			_, _ = w.Write(asanaListResponse(tasks, ""))

		case path == "/projects/P2/project_statuses":
			http.NotFound(w, r)

		case path == "/projects/P2/tasks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))

		case path == "/tasks/T1/stories":
			storiesCallCount++
			if storiesCallCount == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"errors":[{"message":"service unavailable"}]}`))
				return
			}
			if storiesCallCount == 2 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"errors":[{"message":"rate limited"}]}`))
				return
			}
			stories := []map[string]string{
				{"gid": "S1", "type": "comment", "text": "secret-comment-text"},
				{"gid": "S2", "type": "system", "text": "task assigned to user"},
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(asanaListResponse(stories, ""))

		case path == "/tasks/T1/subtasks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))

		case path == "/tasks/T1/attachments":
			w.Header().Set("Content-Type", "application/json")
			attachments := []map[string]string{
				{"gid": "A1", "name": "secret.txt", "host": "asana", "download_url": fmt.Sprintf("http://%s/download/A1", r.Host)},
				{"gid": "A2", "name": "gdoc.pdf", "host": "gdrive", "download_url": "https://drive.google.com/file/d/xxx"},
				{"gid": "A3", "name": "demo.mp4", "host": "asana", "download_url": fmt.Sprintf("http://%s/download/A3", r.Host)},
			}
			_, _ = w.Write(asanaListResponse(attachments, ""))

		case path == "/download/A1":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("secret-bytes"))

		case path == "/download/A3":
			// This should never be called - mp4 is in the skip list.
			mp4DownloadCalled = true
			w.Header().Set("Content-Type", "video/mp4")
			_, _ = w.Write([]byte("fake-video-bytes"))

		default:
			t.Logf("unexpected request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := AsanaConfig{
		Token:              "test-token",
		BaseURL:            ts.URL,
		Workspace:          "W1",
		IncludeAttachments: true,
		RatePerSec:         1000,
		HTTPClient:         ts.Client(),
	}

	e, err := NewAsanaEnumerator(cfg)
	require.NoError(t, err)

	type collected struct {
		content string
		kind    string
		field   string
	}
	var blobs []collected

	ctx := context.Background()
	err = e.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		ep, ok := prov.(types.ExtendedProvenance)
		require.True(t, ok, "expected ExtendedProvenance, got %T", prov)
		kind, _ := ep.Payload["resource"].(string)
		field, _ := ep.Payload["field"].(string)
		blobs = append(blobs, collected{content: string(content), kind: kind, field: field})
		return nil
	})
	require.NoError(t, err)

	type kindField struct{ kind, field string }
	seen := make(map[kindField][]string)
	for _, b := range blobs {
		kf := kindField{b.kind, b.field}
		seen[kf] = append(seen[kf], b.content)
	}

	// Fields that are kept - sentence-like content
	assert.Contains(t, seen[kindField{"team", "description"}], "Engineers team")
	assert.Contains(t, seen[kindField{"project", "notes"}], "Alpha notes")
	assert.Contains(t, seen[kindField{"project_status", "title"}], "On Track")
	assert.Contains(t, seen[kindField{"project_status", "text"}], "Everything is going well")
	assert.Contains(t, seen[kindField{"task", "name"}], "Task One")
	assert.Contains(t, seen[kindField{"task", "notes"}], "task notes here")
	assert.Contains(t, seen[kindField{"story", "text"}], "secret-comment-text")
	assert.Contains(t, seen[kindField{"attachment", "content"}], "secret-bytes")

	// Project brief: only text emitted (title dropped)
	assert.Contains(t, seen[kindField{"project_brief", "text"}], "Alpha brief rich text",
		"brief text must be emitted")

	// Identifier-only fields must NOT be emitted
	assert.Empty(t, seen[kindField{"workspace", "name"}], "workspace.name must not be emitted")
	assert.Empty(t, seen[kindField{"team", "name"}], "team.name must not be emitted")
	assert.Empty(t, seen[kindField{"project", "name"}], "project.name must not be emitted")
	assert.Empty(t, seen[kindField{"project_brief", "title"}], "project_brief.title must not be emitted")

	// Custom field: text type emitted
	assert.Contains(t, seen[kindField{"custom_field", "Connection String"}], "postgres://user:pass@host/db",
		"text custom field value must be emitted with field=name")

	// Custom field: enum type NOT emitted
	for _, b := range blobs {
		if b.kind == "custom_field" && b.field == "Priority" {
			t.Error("enum custom field must not be emitted")
		}
	}

	// task_external: data field emitted
	assert.Contains(t, seen[kindField{"task_external", "data"}], "secret-external-blob",
		"task external data must be emitted")

	// goals: name and notes emitted
	assert.Contains(t, seen[kindField{"goal", "name"}], "Grow Revenue",
		"goal name must be emitted")
	assert.Contains(t, seen[kindField{"goal", "notes"}], "goal notes here",
		"goal notes must be emitted")

	// task templates: name emitted (P1 has one, P2 soft-fails)
	assert.Contains(t, seen[kindField{"task_template", "name"}], "Bug Report Template",
		"task template name must be emitted")

	for _, txt := range seen[kindField{"story", "text"}] {
		assert.NotEqual(t, "task assigned to user", txt, "system story must not be emitted")
	}
	for _, b := range blobs {
		assert.NotContains(t, b.content, "drive.google.com", "gdrive must not be fetched")
	}
	assert.Equal(t, 3, storiesCallCount, "stories must be retried after 5xx and 429")

	// mp4 attachment must be skipped without downloading
	assert.False(t, mp4DownloadCalled, "mp4 download URL must never be hit")
}

func TestAsanaEnumerator_Interface(t *testing.T) {
	var _ Enumerator = (*AsanaEnumerator)(nil)
}

func TestEmitText_SkipsEmpty(t *testing.T) {
	called := false
	cb := func(_ []byte, _ types.BlobID, _ types.Provenance) error {
		called = true
		return nil
	}
	require.NoError(t, emitText("", "W1", "", "task", "T1", "notes", "", cb))
	assert.False(t, called)
	require.NoError(t, emitText("   ", "W1", "", "task", "T1", "notes", "", cb))
	assert.False(t, called)
}

func TestAsanaEnumerator_RateLimiterDoesNotDeadlock(t *testing.T) {
	e, err := NewAsanaEnumerator(AsanaConfig{Token: "tok", RatePerSec: 1000})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, e.client.limiter.Wait(ctx))
	require.NoError(t, e.client.limiter.Wait(ctx))
}

func TestAsanaEnumerator_ScopeProject_NoTeams(t *testing.T) {
	teamsCalled := false
	goalsCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/workspaces/") && strings.HasSuffix(r.URL.Path, "/teams") {
			teamsCalled = true
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
			return
		}
		if r.URL.Path == "/goals" {
			goalsCalled = true
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
			return
		}
		switch r.URL.Path {
		case "/projects/P1":
			proj := map[string]interface{}{
				"gid": "P1", "name": "Solo", "notes": "",
				"workspace": map[string]string{"gid": "W1", "name": "Acme"},
			}
			_, _ = w.Write(asanaResponse(proj))
		case "/workspaces/W1":
			_, _ = w.Write(asanaResponse(map[string]string{"gid": "W1", "name": "Acme"}))
		case "/projects/P1/project_statuses":
			http.NotFound(w, r)
		case "/task_templates":
			http.NotFound(w, r)
		case "/projects/P1/tasks":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := AsanaConfig{Token: "tok", BaseURL: ts.URL, Project: "P1", RatePerSec: 1000, HTTPClient: ts.Client()}
	e, err := NewAsanaEnumerator(cfg)
	require.NoError(t, err)
	require.NoError(t, e.Enumerate(context.Background(), func(_ []byte, _ types.BlobID, _ types.Provenance) error { return nil }))
	assert.False(t, teamsCalled, "teams must not be enumerated when --project is set")
	assert.False(t, goalsCalled, "goals must not be enumerated when --project is set")
}

func TestAsanaEnumerator_ResourceKinds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/workspaces/W1":
			_, _ = w.Write(asanaResponse(map[string]string{"gid": "W1", "name": "WS"}))
		case r.URL.Path == "/workspaces/W1/teams":
			_, _ = w.Write(asanaListResponse([]map[string]string{{"gid": "TM1", "name": "TeamA", "description": "desc"}}, ""))
		case r.URL.Path == "/goals" && r.URL.Query().Get("workspace") == "W1":
			_, _ = w.Write(asanaListResponse([]map[string]string{{"gid": "G1", "name": "A goal", "notes": "goal notes"}}, ""))
		case r.URL.Path == "/workspaces/W1/projects":
			_, _ = w.Write(asanaListResponse([]map[string]string{{"gid": "P1", "name": "Proj", "notes": "notes", "permalink_url": ""}}, ""))
		case r.URL.Path == "/projects/P1/project_statuses":
			http.NotFound(w, r)
		case r.URL.Path == "/task_templates":
			http.NotFound(w, r)
		case r.URL.Path == "/projects/P1/tasks":
			_, _ = w.Write(asanaListResponse([]map[string]string{{"gid": "T1", "name": "Task", "notes": "tnotes", "permalink_url": ""}}, ""))
		case r.URL.Path == "/tasks/T1/stories":
			_, _ = w.Write(asanaListResponse([]map[string]string{{"gid": "S1", "type": "comment", "text": "comment"}}, ""))
		case r.URL.Path == "/tasks/T1/subtasks":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := AsanaConfig{Token: "tok", BaseURL: ts.URL, Workspace: "W1", RatePerSec: 1000, HTTPClient: ts.Client()}
	e, err := NewAsanaEnumerator(cfg)
	require.NoError(t, err)

	var kinds []string
	require.NoError(t, e.Enumerate(context.Background(), func(_ []byte, _ types.BlobID, prov types.Provenance) error {
		ep := prov.(types.ExtendedProvenance)
		kinds = append(kinds, ep.Payload["resource"].(string))
		return nil
	}))

	sort.Strings(kinds)
	assert.Contains(t, kinds, "goal")
	assert.Contains(t, kinds, "project")
	assert.Contains(t, kinds, "task")
	assert.Contains(t, kinds, "story")
	// workspace and team no longer emit name; team emits description only if non-empty
}

func TestAsanaSkipAttachmentExt(t *testing.T) {
	skip := []string{"foo.mp4", "song.mp3", "logo.PNG", "design.fig", "movie.MOV", "font.woff2"}
	keep := []string{"creds.txt", "design.pdf", "config.yaml", "deck.pptx", "data.zip", "noext", "secrets.env"}
	for _, n := range skip {
		if !asanaSkipAttachmentExt(n) {
			t.Errorf("expected skip: %s", n)
		}
	}
	for _, n := range keep {
		if asanaSkipAttachmentExt(n) {
			t.Errorf("expected keep: %s", n)
		}
	}
}

func TestAsanaEnumerator_NoScope_AllWorkspaces(t *testing.T) {
	visitedWorkspaces := make(map[string]bool)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/workspaces":
			workspaces := []map[string]string{
				{"gid": "W1", "name": "Workspace One"},
				{"gid": "W2", "name": "Workspace Two"},
			}
			_, _ = w.Write(asanaListResponse(workspaces, ""))

		case "/workspaces/W1":
			visitedWorkspaces["W1"] = true
			_, _ = w.Write(asanaResponse(map[string]string{"gid": "W1", "name": "Workspace One"}))
		case "/workspaces/W1/teams":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case "/workspaces/W1/projects":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))

		case "/goals":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))

		case "/workspaces/W2":
			visitedWorkspaces["W2"] = true
			_, _ = w.Write(asanaResponse(map[string]string{"gid": "W2", "name": "Workspace Two"}))
		case "/workspaces/W2/teams":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case "/workspaces/W2/projects":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := AsanaConfig{
		Token:      "tok",
		BaseURL:    ts.URL,
		RatePerSec: 1000,
		HTTPClient: ts.Client(),
	}
	e, err := NewAsanaEnumerator(cfg)
	require.NoError(t, err)
	require.NoError(t, e.Enumerate(context.Background(), func(_ []byte, _ types.BlobID, _ types.Provenance) error {
		return nil
	}))

	assert.True(t, visitedWorkspaces["W1"], "W1 must be visited in no-scope mode")
	assert.True(t, visitedWorkspaces["W2"], "W2 must be visited in no-scope mode")
}

func TestAsanaEnumerator_DedupsTaskAcrossProjects(t *testing.T) {
	sharedTask := map[string]string{
		"gid":           "T1",
		"name":          "Shared Task",
		"notes":         "shared-task-notes",
		"permalink_url": "https://app.asana.com/T1",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/workspaces/W1":
			_, _ = w.Write(asanaResponse(map[string]string{"gid": "W1", "name": "Acme"}))
		case r.URL.Path == "/workspaces/W1/teams":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/goals" && r.URL.Query().Get("workspace") == "W1":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/workspaces/W1/projects":
			projects := []map[string]string{
				{"gid": "P1", "name": "Project One", "notes": "alpha notes", "permalink_url": ""},
				{"gid": "P2", "name": "Project Two", "notes": "beta notes", "permalink_url": ""},
			}
			_, _ = w.Write(asanaListResponse(projects, ""))
		case r.URL.Path == "/projects/P1/project_statuses":
			http.NotFound(w, r)
		case r.URL.Path == "/projects/P2/project_statuses":
			http.NotFound(w, r)
		case r.URL.Path == "/task_templates" && r.URL.Query().Get("project") == "P1":
			http.NotFound(w, r)
		case r.URL.Path == "/task_templates" && r.URL.Query().Get("project") == "P2":
			http.NotFound(w, r)
		case r.URL.Path == "/projects/P1/tasks":
			_, _ = w.Write(asanaListResponse([]map[string]string{sharedTask}, ""))
		case r.URL.Path == "/projects/P2/tasks":
			_, _ = w.Write(asanaListResponse([]map[string]string{sharedTask}, ""))
		case r.URL.Path == "/tasks/T1/stories":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/tasks/T1/subtasks":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := AsanaConfig{
		Token:      "test-token",
		BaseURL:    ts.URL,
		Workspace:  "W1",
		RatePerSec: 1000,
		HTTPClient: ts.Client(),
	}
	e, err := NewAsanaEnumerator(cfg)
	require.NoError(t, err)

	type emit struct{ content, resource, field string }
	var emits []emit
	err = e.Enumerate(context.Background(), func(content []byte, _ types.BlobID, prov types.Provenance) error {
		ep := prov.(types.ExtendedProvenance)
		resource, _ := ep.Payload["resource"].(string)
		field, _ := ep.Payload["field"].(string)
		emits = append(emits, emit{string(content), resource, field})
		return nil
	})
	require.NoError(t, err)

	// Count how many times the shared task notes were emitted.
	var sharedCount int
	for _, e := range emits {
		if e.resource == "task" && e.field == "notes" && e.content == "shared-task-notes" {
			sharedCount++
		}
	}
	assert.Equal(t, 1, sharedCount, "shared task notes must appear exactly once (dedup)")

	// Both projects' own notes must be present (proves both P1 and P2 were walked).
	var projectNotes []string
	for _, e := range emits {
		if e.resource == "project" && e.field == "notes" {
			projectNotes = append(projectNotes, e.content)
		}
	}
	assert.Contains(t, projectNotes, "alpha notes", "P1 project notes must be emitted")
	assert.Contains(t, projectNotes, "beta notes", "P2 project notes must be emitted")
}

func TestAsanaEnumerator_DedupsSubtaskAcrossProjects(t *testing.T) {
	sharedSubtask := map[string]string{
		"gid":           "TSHARED",
		"name":          "Shared Subtask",
		"notes":         "shared-subtask-notes",
		"permalink_url": "https://app.asana.com/TSHARED",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/workspaces/W1":
			_, _ = w.Write(asanaResponse(map[string]string{"gid": "W1", "name": "Acme"}))
		case r.URL.Path == "/workspaces/W1/teams":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/goals" && r.URL.Query().Get("workspace") == "W1":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/workspaces/W1/projects":
			projects := []map[string]string{
				{"gid": "P1", "name": "Project One", "notes": "", "permalink_url": ""},
				{"gid": "P2", "name": "Project Two", "notes": "", "permalink_url": ""},
			}
			_, _ = w.Write(asanaListResponse(projects, ""))
		case r.URL.Path == "/projects/P1/project_statuses":
			http.NotFound(w, r)
		case r.URL.Path == "/projects/P2/project_statuses":
			http.NotFound(w, r)
		case r.URL.Path == "/task_templates" && r.URL.Query().Get("project") == "P1":
			http.NotFound(w, r)
		case r.URL.Path == "/task_templates" && r.URL.Query().Get("project") == "P2":
			http.NotFound(w, r)
		case r.URL.Path == "/projects/P1/tasks":
			tasks := []map[string]string{{"gid": "T1", "name": "Task One", "notes": "t1-notes", "permalink_url": ""}}
			_, _ = w.Write(asanaListResponse(tasks, ""))
		case r.URL.Path == "/projects/P2/tasks":
			tasks := []map[string]string{{"gid": "T2", "name": "Task Two", "notes": "t2-notes", "permalink_url": ""}}
			_, _ = w.Write(asanaListResponse(tasks, ""))
		case r.URL.Path == "/tasks/T1/stories":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/tasks/T2/stories":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/tasks/T1/subtasks":
			_, _ = w.Write(asanaListResponse([]map[string]string{sharedSubtask}, ""))
		case r.URL.Path == "/tasks/T2/subtasks":
			// TSHARED is also a subtask of T2 — Asana many-to-many
			_, _ = w.Write(asanaListResponse([]map[string]string{sharedSubtask}, ""))
		case r.URL.Path == "/tasks/TSHARED/stories":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/tasks/TSHARED/subtasks":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := AsanaConfig{
		Token:      "test-token",
		BaseURL:    ts.URL,
		Workspace:  "W1",
		RatePerSec: 1000,
		HTTPClient: ts.Client(),
	}
	e, err := NewAsanaEnumerator(cfg)
	require.NoError(t, err)

	type emit struct{ content, resource, field string }
	var emits []emit
	err = e.Enumerate(context.Background(), func(content []byte, _ types.BlobID, prov types.Provenance) error {
		ep := prov.(types.ExtendedProvenance)
		resource, _ := ep.Payload["resource"].(string)
		field, _ := ep.Payload["field"].(string)
		emits = append(emits, emit{string(content), resource, field})
		return nil
	})
	require.NoError(t, err)

	countTaskNotes := func(notes string) int {
		var n int
		for _, em := range emits {
			if em.resource == "task" && em.field == "notes" && em.content == notes {
				n++
			}
		}
		return n
	}

	assert.Equal(t, 1, countTaskNotes("shared-subtask-notes"), "shared subtask notes must appear exactly once (dedup catches recursive path)")
	assert.Equal(t, 1, countTaskNotes("t1-notes"), "T1 notes must appear exactly once")
	assert.Equal(t, 1, countTaskNotes("t2-notes"), "T2 notes must appear exactly once")
}

func TestAsanaEnumerator_SeenResetsBetweenRuns(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/workspaces/W1":
			_, _ = w.Write(asanaResponse(map[string]string{"gid": "W1", "name": "Acme"}))
		case r.URL.Path == "/workspaces/W1/teams":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/goals" && r.URL.Query().Get("workspace") == "W1":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/workspaces/W1/projects":
			projects := []map[string]string{{"gid": "P1", "name": "Proj", "notes": "", "permalink_url": ""}}
			_, _ = w.Write(asanaListResponse(projects, ""))
		case r.URL.Path == "/projects/P1/project_statuses":
			http.NotFound(w, r)
		case r.URL.Path == "/task_templates" && r.URL.Query().Get("project") == "P1":
			http.NotFound(w, r)
		case r.URL.Path == "/projects/P1/tasks":
			tasks := []map[string]string{{"gid": "T1", "name": "Task One", "notes": "single-task-notes", "permalink_url": ""}}
			_, _ = w.Write(asanaListResponse(tasks, ""))
		case r.URL.Path == "/tasks/T1/stories":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case r.URL.Path == "/tasks/T1/subtasks":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := AsanaConfig{
		Token:      "test-token",
		BaseURL:    ts.URL,
		Workspace:  "W1",
		RatePerSec: 1000,
		HTTPClient: ts.Client(),
	}
	e, err := NewAsanaEnumerator(cfg)
	require.NoError(t, err)

	countEmits := func() int {
		var n int
		err := e.Enumerate(context.Background(), func(content []byte, _ types.BlobID, prov types.Provenance) error {
			ep := prov.(types.ExtendedProvenance)
			resource, _ := ep.Payload["resource"].(string)
			field, _ := ep.Payload["field"].(string)
			if resource == "task" && field == "notes" && string(content) == "single-task-notes" {
				n++
			}
			return nil
		})
		require.NoError(t, err)
		return n
	}

	firstRun := countEmits()
	secondRun := countEmits()
	assert.Equal(t, 1, firstRun, "task notes must appear once on first run")
	assert.Equal(t, 1, secondRun, "task notes must appear once on second run (seen map must reset)")
}

// buildZipBytesWithMember returns the bytes of a zip archive containing one
// member file with the given name and content.
func buildZipBytesWithMember(t *testing.T, memberName, memberContent string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	entry, err := w.Create(memberName)
	require.NoError(t, err)
	_, err = entry.Write([]byte(memberContent))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// asanaBinaryAttachmentServer builds a minimal httptest.Server that serves a
// single workspace → project → task → attachment flow. The attachment download
// response is provided by the caller so tests can inject different payloads.
func asanaBinaryAttachmentServer(t *testing.T, attachmentContent []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/workspaces/W1":
			_, _ = w.Write(asanaResponse(map[string]string{"gid": "W1", "name": "Acme"}))
		case "/workspaces/W1/teams":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case "/goals":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case "/workspaces/W1/projects":
			projects := []map[string]string{{"gid": "P1", "name": "Proj", "notes": "", "permalink_url": ""}}
			_, _ = w.Write(asanaListResponse(projects, ""))
		case "/projects/P1/project_statuses":
			http.NotFound(w, r)
		case "/task_templates":
			http.NotFound(w, r)
		case "/projects/P1/tasks":
			tasks := []map[string]string{{"gid": "T1", "name": "Task", "notes": "", "permalink_url": ""}}
			_, _ = w.Write(asanaListResponse(tasks, ""))
		case "/tasks/T1/stories":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case "/tasks/T1/subtasks":
			_, _ = w.Write(asanaListResponse([]interface{}{}, ""))
		case "/tasks/T1/attachments":
			attachments := []map[string]string{
				{"gid": "A1", "name": "data.zip", "host": "asana",
					"download_url": fmt.Sprintf("http://%s/download/A1", r.Host)},
			}
			_, _ = w.Write(asanaListResponse(attachments, ""))
		case "/download/A1":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(attachmentContent)
		default:
			http.NotFound(w, r)
		}
	}))
}

// TestAsanaEnumerator_BinaryAttachment_SkippedWithoutExtract verifies that a
// binary attachment is silently skipped (no blob emitted) when ExtractArchives
// is empty, locking in the first gate in the attachment loop.
func TestAsanaEnumerator_BinaryAttachment_SkippedWithoutExtract(t *testing.T) {
	// Four bytes that include a null byte so isBinary returns true.
	binaryContent := []byte{'a', 'b', 0x00, 'c'}

	ts := asanaBinaryAttachmentServer(t, binaryContent)
	defer ts.Close()

	cfg := AsanaConfig{
		Token:              "test-token",
		BaseURL:            ts.URL,
		Workspace:          "W1",
		IncludeAttachments: true,
		RatePerSec:         1000,
		HTTPClient:         ts.Client(),
		// Config.ExtractArchives intentionally left empty — gate must fire.
	}

	e, err := NewAsanaEnumerator(cfg)
	require.NoError(t, err)

	var blobs []string
	err = e.Enumerate(context.Background(), func(_ []byte, _ types.BlobID, prov types.Provenance) error {
		ep, ok := prov.(types.ExtendedProvenance)
		require.True(t, ok)
		if resource, _ := ep.Payload["resource"].(string); resource == "attachment" || resource == "attachment_extracted" {
			blobs = append(blobs, resource)
		}
		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, blobs, "binary attachment must not emit any blob when ExtractArchives is empty")
}

// TestAsanaEnumerator_BinaryAttachment_ExtractedWithExtract verifies the happy
// path: when ExtractArchives is "all" and the attachment is a valid zip, the
// extracted member text is emitted with resource "attachment_extracted".
func TestAsanaEnumerator_BinaryAttachment_ExtractedWithExtract(t *testing.T) {
	zipContent := buildZipBytesWithMember(t, "member.txt", "extracted-secret")

	ts := asanaBinaryAttachmentServer(t, zipContent)
	defer ts.Close()

	cfg := AsanaConfig{
		Token:              "test-token",
		BaseURL:            ts.URL,
		Workspace:          "W1",
		IncludeAttachments: true,
		RatePerSec:         1000,
		HTTPClient:         ts.Client(),
		Config: Config{
			ExtractArchives: "all",
			ExtractLimits:   DefaultExtractionLimits(),
		},
	}

	e, err := NewAsanaEnumerator(cfg)
	require.NoError(t, err)

	var extractedTexts []string
	err = e.Enumerate(context.Background(), func(content []byte, _ types.BlobID, prov types.Provenance) error {
		ep, ok := prov.(types.ExtendedProvenance)
		require.True(t, ok)
		if resource, _ := ep.Payload["resource"].(string); resource == "attachment_extracted" {
			extractedTexts = append(extractedTexts, string(content))
		}
		return nil
	})
	require.NoError(t, err)

	assert.Contains(t, extractedTexts, "extracted-secret",
		"extracted zip member text must be emitted with resource=attachment_extracted")
}
