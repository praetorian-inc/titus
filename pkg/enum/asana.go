package enum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/praetorian-inc/titus/pkg/types"
)

// asanaTaskFullFields is the opt_fields set used for per-task GETs that
// hydrate a full asanaTask (notes, custom fields, external data). Shared
// between enumerateTasks and enumerateSubtasks so they cannot silently
// diverge. Read-only — do not mutate at runtime.
var asanaTaskFullFields = url.Values{
	"opt_fields": []string{"name,notes,html_notes,permalink_url,custom_fields.name,custom_fields.text_value,custom_fields.type,custom_fields.gid,external.data"},
}

// Asana does not expose X-RateLimit-Remaining / X-RateLimit-Reset headers.
// The only quota signal is 429 Too Many Requests with Retry-After. We retry
// reactively rather than predictively. See https://developers.asana.com/docs/rate-limits.
const (
	asanaMaxRetries  = 5
	asanaBaseBackoff = 500 * time.Millisecond
	asanaMaxBackoff  = 60 * time.Second
)

// AsanaConfig configures the Asana enumerator.
type AsanaConfig struct {
	Token              string
	BaseURL            string       // Optional; defaults to https://app.asana.com/api/1.0
	Workspace          string       // Workspace GID
	Team               string       // Team GID
	Project            string       // Project GID
	IncludeAttachments bool
	AttachmentMaxBytes int64        // Default 50MB
	RatePerSec         float64      // Default 10.0
	SubtaskDepth       int          // Default 8
	Concurrency        int          // Workers processing tasks within a project; default 5; clamped to [1, 100]
	HTTPClient         *http.Client // Default 60s timeout
	Verbose            io.Writer    // When non-nil, progress messages are written here
	Config                          // Embedded base Config
}

// AsanaEnumerator enumerates content from Asana via the REST API.
type AsanaEnumerator struct {
	client *asanaClient
	cfg    AsanaConfig
	logMu  sync.Mutex
	seenMu sync.Mutex
	seen   map[string]struct{}
}

// NewAsanaEnumerator creates and validates an Asana enumerator.
func NewAsanaEnumerator(cfg AsanaConfig) (*AsanaEnumerator, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("asana token is required")
	}

	baseURL := "https://app.asana.com/api/1.0"
	if cfg.BaseURL != "" {
		if _, err := ValidateBaseURL(cfg.BaseURL); err != nil {
			return nil, fmt.Errorf("asana base URL: %w", err)
		}
		baseURL = strings.TrimRight(cfg.BaseURL, "/")
	}

	if cfg.AttachmentMaxBytes <= 0 {
		cfg.AttachmentMaxBytes = 50 * 1024 * 1024
	}
	if cfg.RatePerSec <= 0 {
		cfg.RatePerSec = 10.0
	}
	if cfg.SubtaskDepth <= 0 {
		cfg.SubtaskDepth = 8
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.Concurrency > 100 {
		cfg.Concurrency = 100
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}

	c := &asanaClient{
		token:      cfg.Token,
		baseURL:    baseURL,
		httpClient: cfg.HTTPClient,
		limiter:    rate.NewLimiter(rate.Limit(cfg.RatePerSec), 1),
	}

	return &AsanaEnumerator{client: c, cfg: cfg}, nil
}

// logf writes a progress message when verbose output is enabled.
// It is safe to call concurrently.
func (e *AsanaEnumerator) logf(format string, args ...interface{}) {
	if e.cfg.Verbose != nil {
		e.logMu.Lock()
		_, _ = fmt.Fprintf(e.cfg.Verbose, format+"\n", args...)
		e.logMu.Unlock()
	}
}

// markSeen records a task GID as scanned this run. Returns true if the GID
// is new (caller should proceed), false if it was already scanned (caller
// should skip). Safe for concurrent use.
func (e *AsanaEnumerator) markSeen(gid string) bool {
	e.seenMu.Lock()
	defer e.seenMu.Unlock()
	if e.seen == nil {
		e.seen = make(map[string]struct{})
	}
	if _, ok := e.seen[gid]; ok {
		return false
	}
	e.seen[gid] = struct{}{}
	return true
}

// alreadySeen reports whether a GID has been recorded by markSeen on this
// run. Used to skip wasted per-item fetches when the same task is reachable
// through multiple projects or subtask trees. Safe for concurrent use.
func (e *AsanaEnumerator) alreadySeen(gid string) bool {
	e.seenMu.Lock()
	defer e.seenMu.Unlock()
	_, ok := e.seen[gid]
	return ok
}

// Enumerate walks Asana resources and yields content blobs.
// When no scope is configured (no workspace/team/project), every workspace
// visible to the PAT is discovered and enumerated in turn.
func (e *AsanaEnumerator) Enumerate(ctx context.Context, cb func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	e.seenMu.Lock()
	e.seen = make(map[string]struct{})
	e.seenMu.Unlock()

	var cbMu sync.Mutex
	safeCb := func(content []byte, id types.BlobID, prov types.Provenance) error {
		cbMu.Lock()
		defer cbMu.Unlock()
		return cb(content, id, prov)
	}

	if e.cfg.Workspace == "" && e.cfg.Team == "" && e.cfg.Project == "" {
		// Workspaces are bounded (a token typically sees < 10), so it's safe to
		// collect them up-front. Tasks/subtasks/stories MUST stream — see paginate.
		var workspaces []asanaWorkspace
		if err := e.client.paginate(ctx, "/workspaces", url.Values{"opt_fields": []string{"name"}}, func(raw json.RawMessage) error {
			var page []asanaWorkspace
			if err := json.Unmarshal(raw, &page); err != nil {
				return err
			}
			workspaces = append(workspaces, page...)
			return nil
		}); err != nil {
			return fmt.Errorf("listing workspaces: %w", err)
		}
		e.logf("Discovered %d workspaces visible to token", len(workspaces))
		for _, ws := range workspaces {
			if err := e.enumerateWorkspace(ctx, ws.GID, safeCb); err != nil {
				return err
			}
		}
		return nil
	}

	workspaceGID, err := e.resolveWorkspaceGID(ctx)
	if err != nil {
		return err
	}
	return e.enumerateWorkspace(ctx, workspaceGID, safeCb)
}

// enumerateWorkspace scans a single workspace by GID.
func (e *AsanaEnumerator) enumerateWorkspace(ctx context.Context, workspaceGID string, cb func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	var ws asanaWorkspace
	if err := e.client.get(ctx, "/workspaces/"+workspaceGID, nil, &ws); err != nil {
		return fmt.Errorf("fetching workspace: %w", err)
	}
	e.logf("Entering workspace %q (gid=%s)", ws.Name, workspaceGID)

	var teamCount int
	// Teams and goals - skip when scoped to a single project
	if e.cfg.Project == "" {
		n, err := e.enumerateTeams(ctx, workspaceGID, cb)
		if err != nil {
			return err
		}
		teamCount = n
		// Goals - soft-fail: some workspaces don't have goals enabled
		if err := e.enumerateGoals(ctx, workspaceGID, cb); err != nil {
			e.logf("Warning: goals: %v", err)
		}
	}

	projectCount, err := e.enumerateProjects(ctx, workspaceGID, cb)
	if err != nil {
		return err
	}

	e.logf("Workspace %q: %d teams, %d projects", ws.Name, teamCount, projectCount)
	return nil
}

// resolveWorkspaceGID derives the workspace GID from config.
func (e *AsanaEnumerator) resolveWorkspaceGID(ctx context.Context) (string, error) {
	if e.cfg.Workspace != "" {
		return e.cfg.Workspace, nil
	}

	if e.cfg.Project != "" {
		var proj struct {
			GID       string `json:"gid"`
			Workspace struct {
				GID  string `json:"gid"`
				Name string `json:"name"`
			} `json:"workspace"`
		}
		params := url.Values{"opt_fields": []string{"workspace.name"}}
		if err := e.client.get(ctx, "/projects/"+e.cfg.Project, params, &proj); err != nil {
			return "", fmt.Errorf("fetching project to resolve workspace: %w", err)
		}
		return proj.Workspace.GID, nil
	}

	// Team path
	var team struct {
		GID          string `json:"gid"`
		Organization struct {
			GID  string `json:"gid"`
			Name string `json:"name"`
		} `json:"organization"`
	}
	params := url.Values{"opt_fields": []string{"organization.name"}}
	if err := e.client.get(ctx, "/teams/"+e.cfg.Team, params, &team); err != nil {
		return "", fmt.Errorf("fetching team to resolve workspace: %w", err)
	}
	return team.Organization.GID, nil
}

// asanaWorkspace holds the minimal workspace fields we need.
type asanaWorkspace struct {
	GID  string `json:"gid"`
	Name string `json:"name"`
}

// asanaTeam holds the minimal team fields we scan.
type asanaTeam struct {
	GID         string `json:"gid"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (e *AsanaEnumerator) enumerateTeams(ctx context.Context, workspaceGID string, cb func([]byte, types.BlobID, types.Provenance) error) (int, error) {
	params := url.Values{"opt_fields": []string{"name,description"}}

	if e.cfg.Team != "" {
		var t asanaTeam
		if err := e.client.get(ctx, "/teams/"+e.cfg.Team, params, &t); err != nil {
			return 0, fmt.Errorf("fetching team: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := e.emitText(t.Description, workspaceGID, "", "team", t.GID, "description", "", cb); err != nil {
			return 0, err
		}
		return 1, nil
	}

	var count int
	if err := e.client.paginate(ctx, "/workspaces/"+workspaceGID+"/teams", params, func(raw json.RawMessage) error {
		var page []asanaTeam
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, t := range page {
			count++
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := e.emitText(t.Description, workspaceGID, "", "team", t.GID, "description", "", cb); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return 0, fmt.Errorf("listing teams: %w", err)
	}
	return count, nil
}

// asanaProject holds the minimal project fields we scan.
type asanaProject struct {
	GID          string `json:"gid"`
	Name         string `json:"name"`
	Notes        string `json:"notes"`
	HTMLNotes    string `json:"html_notes"`
	PermalinkURL string `json:"permalink_url"`
	Brief        *struct {
		GID string `json:"gid"`
	} `json:"brief"`
}

// asanaProjectBrief holds the rich-text brief attached to a project.
type asanaProjectBrief struct {
	GID      string `json:"gid"`
	Title    string `json:"title"`
	Text     string `json:"text"`
	HTMLText string `json:"html_text"`
}

// asanaCustomField is one custom field on a task.
type asanaCustomField struct {
	GID       string `json:"gid"`
	Name      string `json:"name"`
	Type      string `json:"type"`       // "text", "number", "enum", etc.
	TextValue string `json:"text_value"` // populated only when Type=="text"
}

// asanaTask holds the minimal task fields we scan.
type asanaTask struct {
	GID          string             `json:"gid"`
	Name         string             `json:"name"`
	Notes        string             `json:"notes"`
	HTMLNotes    string             `json:"html_notes"`
	PermalinkURL string             `json:"permalink_url"`
	CustomFields []asanaCustomField `json:"custom_fields"`
	External     *struct {
		Data string `json:"data"`
	} `json:"external"`
}

func (e *AsanaEnumerator) enumerateProjects(ctx context.Context, workspaceGID string, cb func([]byte, types.BlobID, types.Provenance) error) (int, error) {
	fullParams := url.Values{"opt_fields": []string{"name,notes,html_notes,permalink_url,brief.gid"}}

	switch {
	case e.cfg.Project != "":
		var p asanaProject
		if err := e.client.get(ctx, "/projects/"+e.cfg.Project, fullParams, &p); err != nil {
			return 0, fmt.Errorf("fetching project: %w", err)
		}
		e.logf("Entering project %q (gid=%s)", p.Name, p.GID)
		tasksScanned, err := e.enumerateProject(ctx, workspaceGID, p, cb)
		if err != nil {
			return 0, err
		}
		e.logf("Project %q: %d tasks", p.Name, tasksScanned)
		return 1, nil

	case e.cfg.Team != "":
		gids, err := e.listGIDs(ctx, "/teams/"+e.cfg.Team+"/projects")
		if err != nil {
			return 0, fmt.Errorf("listing team projects: %w", err)
		}
		e.logf("Discovered %d projects in team %s", len(gids), e.cfg.Team)
		return e.fetchAndEnumerateProjects(ctx, workspaceGID, gids, fullParams, cb)

	default:
		gids, err := e.listGIDs(ctx, "/workspaces/"+workspaceGID+"/projects")
		if err != nil {
			return 0, fmt.Errorf("listing workspace projects: %w", err)
		}
		e.logf("Discovered %d projects in workspace %s", len(gids), workspaceGID)
		return e.fetchAndEnumerateProjects(ctx, workspaceGID, gids, fullParams, cb)
	}
}

// fetchAndEnumerateProjects fetches each project by GID with full opt_fields
// and dispatches to enumerateProject. Soft-fails individual fetches.
func (e *AsanaEnumerator) fetchAndEnumerateProjects(ctx context.Context, workspaceGID string, gids []string, fullParams url.Values, cb func([]byte, types.BlobID, types.Provenance) error) (int, error) {
	var count int
	for _, gid := range gids {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		var p asanaProject
		if err := e.client.get(ctx, "/projects/"+gid, fullParams, &p); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return count, ctxErr
			}
			e.logf("Warning: fetching project %s: %v", gid, err)
			continue
		}
		count++
		e.logf("Entering project %q (gid=%s)", p.Name, p.GID)
		tasksScanned, err := e.enumerateProject(ctx, workspaceGID, p, cb)
		if err != nil {
			return count, err
		}
		e.logf("Project %q: %d tasks", p.Name, tasksScanned)
	}
	return count, nil
}

func (e *AsanaEnumerator) enumerateProject(ctx context.Context, workspaceGID string, p asanaProject, cb func([]byte, types.BlobID, types.Provenance) error) (int, error) {
	if err := e.emitText(p.Notes, workspaceGID, p.PermalinkURL, "project", p.GID, "notes", "", cb); err != nil {
		return 0, err
	}
	if err := e.emitText(p.HTMLNotes, workspaceGID, p.PermalinkURL, "project", p.GID, "html_notes", "", cb); err != nil {
		return 0, err
	}

	// Project brief - soft-fail: some projects 403 if user can't see the brief
	if p.Brief != nil && p.Brief.GID != "" {
		if err := e.enumerateProjectBrief(ctx, workspaceGID, p.GID, p.Brief.GID, p.PermalinkURL, cb); err != nil {
			e.logf("Warning: project %s brief %s: %v", p.GID, p.Brief.GID, err)
		}
	}

	// Project statuses - soft-fail: some projects 404 this endpoint
	if err := e.enumerateProjectStatuses(ctx, workspaceGID, p.GID, cb); err != nil {
		e.logf("Warning: project %s statuses: %v", p.GID, err)
	}

	// Task templates - soft-fail: not available on all Asana tiers
	if err := e.enumerateTaskTemplates(ctx, workspaceGID, p.GID, p.PermalinkURL, cb); err != nil {
		e.logf("Warning: project %s task templates: %v", p.GID, err)
	}

	return e.enumerateTasks(ctx, workspaceGID, p.GID, cb)
}

func (e *AsanaEnumerator) enumerateProjectBrief(ctx context.Context, workspaceGID, projectGID, briefGID, projectPermalink string, cb func([]byte, types.BlobID, types.Provenance) error) error {
	var brief asanaProjectBrief
	params := url.Values{"opt_fields": []string{"text,html_text"}}
	if err := e.client.get(ctx, "/project_briefs/"+briefGID, params, &brief); err != nil {
		return err
	}
	if err := e.emitText(brief.Text, workspaceGID, projectPermalink, "project_brief", briefGID, "text", projectGID, cb); err != nil {
		return err
	}
	return e.emitText(brief.HTMLText, workspaceGID, projectPermalink, "project_brief", briefGID, "html_text", projectGID, cb)
}

// asanaGoal holds the minimal goal fields we scan.
type asanaGoal struct {
	GID          string `json:"gid"`
	Name         string `json:"name"`
	Notes        string `json:"notes"`
	HTMLNotes    string `json:"html_notes"`
	PermalinkURL string `json:"permalink_url"`
}

func (e *AsanaEnumerator) enumerateGoals(ctx context.Context, workspaceGID string, cb func([]byte, types.BlobID, types.Provenance) error) error {
	params := url.Values{"opt_fields": []string{"name,notes,html_notes,permalink_url"}}
	if e.cfg.Team != "" {
		params.Set("team", e.cfg.Team)
	} else {
		params.Set("workspace", workspaceGID)
	}
	return e.client.paginate(ctx, "/goals", params, func(raw json.RawMessage) error {
		var page []asanaGoal
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, g := range page {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := e.emitText(g.Name, workspaceGID, g.PermalinkURL, "goal", g.GID, "name", "", cb); err != nil {
				return err
			}
			if err := e.emitText(g.Notes, workspaceGID, g.PermalinkURL, "goal", g.GID, "notes", "", cb); err != nil {
				return err
			}
			if err := e.emitText(g.HTMLNotes, workspaceGID, g.PermalinkURL, "goal", g.GID, "html_notes", "", cb); err != nil {
				return err
			}
		}
		return nil
	})
}

// asanaTaskTemplate holds the minimal task template fields we scan.
type asanaTaskTemplate struct {
	GID  string `json:"gid"`
	Name string `json:"name"`
}

func (e *AsanaEnumerator) enumerateTaskTemplates(ctx context.Context, workspaceGID, projectGID, projectPermalink string, cb func([]byte, types.BlobID, types.Provenance) error) error {
	params := url.Values{
		"project":    []string{projectGID},
		"opt_fields": []string{"name"},
	}
	return e.client.paginate(ctx, "/task_templates", params, func(raw json.RawMessage) error {
		var page []asanaTaskTemplate
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, tmpl := range page {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := e.emitText(tmpl.Name, workspaceGID, projectPermalink, "task_template", tmpl.GID, "name", projectGID, cb); err != nil {
				return err
			}
		}
		return nil
	})
}

// asanaProjectStatus holds the minimal status fields we scan.
type asanaProjectStatus struct {
	GID      string `json:"gid"`
	Title    string `json:"title"`
	Text     string `json:"text"`
	HTMLText string `json:"html_text"`
}

func (e *AsanaEnumerator) enumerateProjectStatuses(ctx context.Context, workspaceGID, projectGID string, cb func([]byte, types.BlobID, types.Provenance) error) error {
	params := url.Values{"opt_fields": []string{"title,text,html_text"}}
	return e.client.paginate(ctx, "/projects/"+projectGID+"/project_statuses", params, func(raw json.RawMessage) error {
		var page []asanaProjectStatus
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, st := range page {
			if err := e.emitText(st.Title, workspaceGID, "", "project_status", st.GID, "title", "", cb); err != nil {
				return err
			}
			if err := e.emitText(st.Text, workspaceGID, "", "project_status", st.GID, "text", "", cb); err != nil {
				return err
			}
			if err := e.emitText(st.HTMLText, workspaceGID, "", "project_status", st.GID, "html_text", "", cb); err != nil {
				return err
			}
		}
		return nil
	})
}

func (e *AsanaEnumerator) enumerateTasks(ctx context.Context, workspaceGID, projectGID string, cb func([]byte, types.BlobID, types.Provenance) error) (int, error) {
	gids, err := e.listGIDs(ctx, "/projects/"+projectGID+"/tasks")
	if err != nil {
		return 0, fmt.Errorf("listing tasks for project %s: %w", projectGID, err)
	}
	e.logf("Listed %d tasks in project %s", len(gids), projectGID)

	concurrency := e.cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	var taskCount int64
	for _, gid := range gids {
		gid := gid // shadow for closure
		g.Go(func() error {
			if gctx.Err() != nil {
				return gctx.Err()
			}
			if e.alreadySeen(gid) {
				return nil
			}
			var t asanaTask
			if err := e.client.get(gctx, "/tasks/"+gid, asanaTaskFullFields, &t); err != nil {
				if ctxErr := gctx.Err(); ctxErr != nil {
					return ctxErr
				}
				e.logf("Warning: fetching task %s: %v", gid, err)
				return nil
			}
			e.logf("Processing task %q (gid=%s)", truncateForLog(t.Name, 80), t.GID)
			if err := e.enumerateTask(gctx, workspaceGID, t, 0, cb); err != nil {
				return err
			}
			atomic.AddInt64(&taskCount, 1)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return int(atomic.LoadInt64(&taskCount)), err
	}
	return int(atomic.LoadInt64(&taskCount)), nil
}

func (e *AsanaEnumerator) enumerateTask(ctx context.Context, workspaceGID string, t asanaTask, depth int, cb func([]byte, types.BlobID, types.Provenance) error) error {
	if !e.markSeen(t.GID) {
		e.logf("Skipping task %q (gid=%s): already scanned this run", truncateForLog(t.Name, 80), t.GID)
		return nil
	}
	if err := e.emitText(t.Name, workspaceGID, t.PermalinkURL, "task", t.GID, "name", "", cb); err != nil {
		return err
	}
	if err := e.emitText(t.Notes, workspaceGID, t.PermalinkURL, "task", t.GID, "notes", "", cb); err != nil {
		return err
	}
	if err := e.emitText(t.HTMLNotes, workspaceGID, t.PermalinkURL, "task", t.GID, "html_notes", "", cb); err != nil {
		return err
	}

	// Emit external integration data
	if t.External != nil && t.External.Data != "" {
		if err := e.emitText(t.External.Data, workspaceGID, t.PermalinkURL, "task_external", t.GID, "data", "", cb); err != nil {
			return err
		}
	}

	// Emit text custom fields
	for _, cf := range t.CustomFields {
		if cf.Type != "text" || strings.TrimSpace(cf.TextValue) == "" {
			continue
		}
		fieldName := strings.TrimSpace(cf.Name)
		if fieldName == "" {
			fieldName = cf.GID
		}
		if err := e.emitText(cf.TextValue, workspaceGID, t.PermalinkURL, "custom_field", cf.GID, fieldName, t.GID, cb); err != nil {
			return err
		}
	}

	if err := e.listAndEmitStories(ctx, workspaceGID, t, cb); err != nil {
		return err
	}

	if depth < e.cfg.SubtaskDepth {
		if err := e.enumerateSubtasks(ctx, workspaceGID, t.GID, depth, cb); err != nil {
			e.logf("Warning: subtasks for task %s: %v", t.GID, err)
		}
	}

	if e.cfg.IncludeAttachments {
		if err := e.enumerateAttachments(ctx, workspaceGID, t.GID, t.PermalinkURL, cb); err != nil {
			return err
		}
	}

	return nil
}

// listAndEmitStories streams stories for a task and emits comment stories.
func (e *AsanaEnumerator) listAndEmitStories(ctx context.Context, workspaceGID string, t asanaTask, cb func([]byte, types.BlobID, types.Provenance) error) error {
	params := url.Values{"opt_fields": []string{"text,type"}}
	if err := e.client.paginate(ctx, "/tasks/"+t.GID+"/stories", params, func(raw json.RawMessage) error {
		var page []asanaStory
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, s := range page {
			if s.Type != "comment" {
				continue // skip system stories (noise)
			}
			storyPath := t.PermalinkURL
			if storyPath == "" {
				storyPath = fmt.Sprintf("asana://story/%s", s.GID)
			}
			prov := types.ExtendedProvenance{Payload: map[string]interface{}{
				"source":     "asana",
				"workspace":  workspaceGID,
				"resource":   "story",
				"gid":        s.GID,
				"field":      "text",
				"parent_gid": t.GID,
				"permalink":  t.PermalinkURL,
				"path":       storyPath,
			}}
			if err := emitWithProv(s.Text, prov, cb); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("listing stories for task %s: %w", t.GID, err)
	}
	return nil
}

func (e *AsanaEnumerator) enumerateSubtasks(ctx context.Context, workspaceGID, taskGID string, depth int, cb func([]byte, types.BlobID, types.Provenance) error) error {
	gids, err := e.listGIDs(ctx, "/tasks/"+taskGID+"/subtasks")
	if err != nil {
		return err
	}

	for _, gid := range gids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.alreadySeen(gid) {
			continue
		}
		var st asanaTask
		if err := e.client.get(ctx, "/tasks/"+gid, asanaTaskFullFields, &st); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			e.logf("Warning: fetching subtask %s: %v", gid, err)
			continue
		}
		if err := e.enumerateTask(ctx, workspaceGID, st, depth+1, cb); err != nil {
			return err
		}
	}
	return nil
}

// asanaAttachment holds the minimal attachment fields we need.
type asanaAttachment struct {
	GID         string `json:"gid"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	DownloadURL string `json:"download_url"`
}

func (e *AsanaEnumerator) enumerateAttachments(ctx context.Context, workspaceGID, taskGID, taskPermalink string, cb func([]byte, types.BlobID, types.Provenance) error) error {
	params := url.Values{"opt_fields": []string{"name,host,download_url"}}
	return e.client.paginate(ctx, "/tasks/"+taskGID+"/attachments", params, func(raw json.RawMessage) error {
		var page []asanaAttachment
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, att := range page {
			if att.Host != "asana" {
				continue // external attachments (gdrive/box/dropbox) not proxied by Asana
			}
			if asanaSkipAttachmentExt(att.Name) {
				continue
			}
			content, err := e.client.downloadRaw(ctx, att.DownloadURL, e.cfg.AttachmentMaxBytes)
			if err != nil {
				e.logf("Warning: download attachment %q: %v", att.Name, err)
				continue // soft-fail individual download errors
			}

			if int64(len(content)) > e.cfg.AttachmentMaxBytes {
				e.logf("Skipping attachment %q: exceeded max size (%d bytes)", att.Name, e.cfg.AttachmentMaxBytes)
				continue
			}

			if isBinary(content) {
				// Binary attachment: extract text from supported archive/document formats
				// when the user has opted into extraction via --extract. Never emit raw
				// binary to the matcher — regexp2 NFA blows up on rune-decoded binary
				// content.
				if e.cfg.ExtractArchives == "" {
					continue
				}
				ext := getExtension(att.Name)
				if !shouldExtract(e.cfg.Config, ext) {
					continue
				}
				extractLimits := e.cfg.ExtractLimits
				if extractLimits.MaxSize == 0 && extractLimits.MaxTotal == 0 {
					extractLimits = DefaultExtractionLimits()
				}
				extracted, err := ExtractText(att.Name, content, extractLimits)
				if err != nil {
					continue
				}
				for _, ec := range extracted {
					if len(ec.Content) == 0 {
						continue
					}
					extProv := types.ExtendedProvenance{Payload: map[string]interface{}{
						"source":          "asana",
						"workspace":       workspaceGID,
						"resource":        "attachment_extracted",
						"gid":             att.GID,
						"field":           "content",
						"parent_gid":      taskGID,
						"attachment":      att.Name,
						"extracted_entry": ec.Name,
						"permalink":       taskPermalink,
						"path":            fmt.Sprintf("asana://attachment/%s/%s", taskGID, att.GID),
					}}
					if err := emitWithProv(string(ec.Content), extProv, cb); err != nil {
						return err
					}
				}
				continue
			}

			// Plain text attachment — emit raw bytes.
			rawProv := types.ExtendedProvenance{Payload: map[string]interface{}{
				"source":     "asana",
				"workspace":  workspaceGID,
				"resource":   "attachment",
				"gid":        att.GID,
				"field":      "content",
				"parent_gid": taskGID,
				"attachment": att.Name,
				"permalink":  taskPermalink,
				"path":       fmt.Sprintf("asana://attachment/%s/%s", taskGID, att.GID),
			}}
			if err := emitWithProv(string(content), rawProv, cb); err != nil {
				return err
			}
		}
		return nil
	})
}

// listGIDs paginates path with opt_fields=gid and returns the collected GIDs.
// Used as Phase 1 of the two-phase list-then-fetch pattern that avoids holding
// pagination tokens open while we enumerate items deeply. Skips entries with
// empty GIDs defensively.
func (e *AsanaEnumerator) listGIDs(ctx context.Context, path string) ([]string, error) {
	params := url.Values{"opt_fields": []string{"gid"}}
	var gids []string
	err := e.client.paginate(ctx, path, params, func(raw json.RawMessage) error {
		var page []struct {
			GID string `json:"gid"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, item := range page {
			if item.GID == "" {
				continue
			}
			gids = append(gids, item.GID)
		}
		return nil
	})
	return gids, err
}

// emitText yields a non-empty text field as a blob with standard Asana provenance.
func emitText(text, workspaceGID, permalink, resource, gid, field, parentGID string, cb func([]byte, types.BlobID, types.Provenance) error) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	path := permalink
	if path == "" {
		path = fmt.Sprintf("asana://%s/%s", resource, gid)
	}
	payload := map[string]interface{}{
		"source":    "asana",
		"workspace": workspaceGID,
		"resource":  resource,
		"gid":       gid,
		"field":     field,
		"permalink": permalink,
		"path":      path,
	}
	if parentGID != "" {
		payload["parent_gid"] = parentGID
	}
	return emitWithProv(text, types.ExtendedProvenance{Payload: payload}, cb)
}

// emitText is the method form of the free function emitText. It enforces
// MaxFileSize for task-content blobs (notes, comments, custom fields, etc.)
// before delegating to the free function. MaxFileSize=0 means unlimited.
func (e *AsanaEnumerator) emitText(text, workspaceGID, permalink, resource, gid, field, parentGID string, cb func([]byte, types.BlobID, types.Provenance) error) error {
	if e.cfg.MaxFileSize > 0 && int64(len(text)) > e.cfg.MaxFileSize {
		e.logf("Skipping %s field %q: exceeds max size (%d bytes)", resource, field, e.cfg.MaxFileSize)
		return nil
	}
	return emitText(text, workspaceGID, permalink, resource, gid, field, parentGID, cb)
}

// emitWithProv yields non-empty text content with a pre-built provenance.
func emitWithProv(text string, prov types.Provenance, cb func([]byte, types.BlobID, types.Provenance) error) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	content := []byte(text)
	return cb(content, types.ComputeBlobID(content), prov)
}

// ─── HTTP client ──────────────────────────────────────────────────────────────

type asanaClient struct {
	token      string
	baseURL    string
	httpClient *http.Client
	limiter    *rate.Limiter
}

// asanaEnvelope is the outer JSON wrapper for all Asana API responses.
type asanaEnvelope struct {
	Data     json.RawMessage `json:"data"`
	NextPage *struct {
		Offset string `json:"offset"`
	} `json:"next_page"`
}

// get fetches a single resource and decodes its "data" field into out.
func (c *asanaClient) get(ctx context.Context, path string, params url.Values, out interface{}) error {
	raw, err := c.doRequest(ctx, c.baseURL+path, params)
	if err != nil {
		return err
	}

	var env asanaEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return json.Unmarshal(env.Data, out)
}

// paginate calls onPage for each page of results. Callers MUST process items
// inside the callback — accumulating into a slice causes memory exhaustion on
// large tenants (subtask recursion compounds).
func (c *asanaClient) paginate(ctx context.Context, path string, params url.Values, onPage func(json.RawMessage) error) error {
	p := make(url.Values)
	for k, v := range params {
		p[k] = v
	}
	p.Set("limit", "100")

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := c.doRequest(ctx, c.baseURL+path, p)
		if err != nil {
			return err
		}

		var env asanaEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return fmt.Errorf("decoding page: %w", err)
		}

		if err := onPage(env.Data); err != nil {
			return err
		}

		if env.NextPage == nil || env.NextPage.Offset == "" {
			break
		}
		p.Set("offset", env.NextPage.Offset)
	}
	return nil
}

// downloadRaw fetches a presigned S3 URL without the Asana Bearer token.
// The download_url is a temporary presigned S3 URL - sending the Bearer header
// would leak the Asana token to AWS.
func (c *asanaClient) downloadRaw(ctx context.Context, downloadURL string, maxBytes int64) ([]byte, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attachment download: HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
}

// retryDelay returns the sleep duration before the next attempt.
// If retryAfterHeader parses to a positive integer of seconds, that value
// (capped at maxBackoff) is returned. Otherwise exponential backoff with
// jitter is used: min(2^attempt * asanaBaseBackoff + jitter, maxBackoff).
func retryDelay(attempt int, retryAfterHeader string, maxBackoff time.Duration) time.Duration {
	if secs, err := strconv.Atoi(retryAfterHeader); err == nil && secs > 0 {
		d := time.Duration(secs) * time.Second
		if d > maxBackoff {
			return maxBackoff
		}
		return d
	}
	// #nosec G115 -- attempt is bounded by asanaMaxRetries (5); shift is safe.
	exp := time.Duration(1<<uint(attempt)) * asanaBaseBackoff
	// #nosec G404 -- jitter for retry backoff; cryptographic randomness unnecessary.
	jitter := time.Duration(rand.Int63n(int64(time.Second)))
	d := exp + jitter
	if d > maxBackoff {
		return maxBackoff
	}
	return d
}

// doRequest executes an authenticated GET, retrying on 429 and transient 5xx
// errors (500, 502, 503, 504) up to asanaMaxRetries times with exponential
// backoff and jitter. Retry-After is honoured on both 429 and 5xx responses.
func (c *asanaClient) doRequest(ctx context.Context, rawURL string, params url.Values) ([]byte, error) {
	for attempt := 0; attempt < asanaMaxRetries; attempt++ {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		if len(params) > 0 {
			req.URL.RawQuery = params.Encode()
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("reading response: %w", readErr)
		}

		switch resp.StatusCode {
		case http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			if attempt == asanaMaxRetries-1 {
				return nil, fmt.Errorf("HTTP %d: request failed after %d attempts", resp.StatusCode, asanaMaxRetries)
			}
			wait := retryDelay(attempt, resp.Header.Get("Retry-After"), asanaMaxBackoff)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			trimmed := strings.TrimSpace(string(body))
			if len(trimmed) > 200 {
				trimmed = trimmed[:200]
			}
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trimmed)
		}

		return body, nil
	}

	return nil, fmt.Errorf("request failed after %d attempts", asanaMaxRetries)
}

// asanaStory is a task comment or system event.
type asanaStory struct {
	GID  string `json:"gid"`
	Type string `json:"type"`
	Text string `json:"text"`
}

// truncateForLog clips long strings (e.g. task names) for log readability.
func truncateForLog(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
