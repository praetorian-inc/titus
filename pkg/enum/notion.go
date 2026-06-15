package enum

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/titus/pkg/types"
)

const notionAPIBase = "https://www.notion.so/api/v3"

// NotionConfig configures the Notion workspace enumerator.
type NotionConfig struct {
	Token       string    // token_v2 session cookie
	Concurrency int       // parallel workers (default 3)
	RateLimit   float64   // requests per second (default 3)
	Verbose     io.Writer // progress output (nil = silent)
	PageID      string    // scan only this page (URL or ID); empty = full workspace
	Workspace   string    // workspace name or ID filter
	Teamspace   string    // teamspace name or ID filter
}

// NotionEnumerator enumerates blobs from a Notion workspace via the internal API.
type NotionEnumerator struct {
	config  NotionConfig
	client  *http.Client
	limiter *rate.Limiter
}

// notionProvenance builds an ExtendedProvenance for a Notion page.
func notionProvenance(pageID, title, pageURL, space string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source": "notion",
			"pageID": pageID,
			"title":  title,
			"url":    pageURL,
			"path":   pageURL,
			"space":  space,
		},
	}
}

// NewNotionEnumerator creates a new Notion enumerator.
func NewNotionEnumerator(cfg NotionConfig) (*NotionEnumerator, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("notion token_v2 is required")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 3
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 3.0
	}
	return &NotionEnumerator{
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
	}, nil
}

// logf writes a progress message when verbose output is enabled.
func (e *NotionEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
}

// progressf writes an in-place progress update (no trailing newline) using \r.
// The %-80s left-pads to 80 chars to clear any leftover characters from the previous line.
func (e *NotionEnumerator) progressf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s", fmt.Sprintf(format, args...))
	}
}

// Enumerate discovers all pages in the Notion workspace using flat discovery
// (getSpaces + search) and then classifies/renders them concurrently.
// This avoids the per-page BFS approach which is too slow at 3 req/sec.
func (e *NotionEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Single-page mode: skip discovery, scan just this page.
	if e.config.PageID != "" {
		pageID := parseNotionPageID(e.config.PageID)

		// Get workspace name for provenance
		_, spaceName, _, _ := e.discoverWorkspace(ctx)
		if spaceName == "" {
			spaceName = "Notion"
		}

		e.logf("Scanning single page: %s", pageID)

		rendered, err := e.renderPage(ctx, pageID)
		if err != nil {
			return fmt.Errorf("loading page %s: %w", pageID, err)
		}
		if rendered == "" {
			e.logf("Page is empty")
			return nil
		}

		// Get title
		bv, _ := e.loadPageChunkSingle(ctx, pageID)
		title := ""
		if bv != nil {
			title = nExtractTitle(bv)
		}
		if title == "" {
			title = pageID
		}

		pageURL := fmt.Sprintf("https://www.notion.so/%s", nCleanID(pageID))
		blob := nBuildBlob(title, pageURL, spaceName, rendered)
		blobID := types.ComputeBlobID(blob)
		prov := notionProvenance(pageID, title, pageURL, spaceName)

		return callback(blob, blobID, prov)
	}

	// Phase 1: Discover workspace.
	spaceID, spaceName, topBlockIDs, err := e.discoverWorkspace(ctx)
	if err != nil {
		return fmt.Errorf("discovering workspace: %w", err)
	}
	if spaceID == "" {
		return fmt.Errorf("no workspace found")
	}
	e.logf("Workspace: %s (id: %s)", spaceName, spaceID)
	e.logf("Found %d root page IDs from workspace", len(topBlockIDs))

	// Resolve teamspace filter if set.
	var teamID string
	if e.config.Teamspace != "" {
		tid, tname, err := e.resolveTeamID(ctx, spaceID, e.config.Teamspace)
		if err != nil {
			return err
		}
		teamID = tid
		e.logf("Teamspace: %s (id: %s)", tname, tid)
	}

	// Phase 2: Collect page IDs from all sources (no per-page API calls).
	seen := make(map[string]bool)
	var allIDs []string
	// When teamspace is active, skip workspace-wide roots and rely only on search.
	if teamID == "" {
		for _, id := range topBlockIDs {
			if !seen[id] {
				seen[id] = true
				allIDs = append(allIDs, id)
			}
		}
	}
	searchIDs, searchErr := e.searchBlockIDs(ctx, spaceID, teamID)
	if searchErr != nil {
		if teamID != "" {
			// In teamspace mode, search is the primary discovery source.
			return fmt.Errorf("search failed in teamspace mode: %w", searchErr)
		}
		e.logf("Warning: search failed (continuing with workspace roots): %v", searchErr)
	}
	for _, id := range searchIDs {
		if !seen[id] {
			seen[id] = true
			allIDs = append(allIDs, id)
		}
	}
	totalIDs := len(allIDs)
	e.logf("Discovered %d total unique page IDs", totalIDs)

	// Phase 3: Classify and render pages concurrently.
	var scanned atomic.Int64

	type dbInfo struct {
		collectionID string
		viewID       string
		title        string
	}
	var dbMu sync.Mutex
	var databases []dbInfo

	var callbackMu sync.Mutex

	pageCh := make(chan string, len(allIDs))
	for _, id := range allIDs {
		pageCh <- id
	}
	close(pageCh)

	var firstErr error
	var errOnce sync.Once

	var wg sync.WaitGroup
	for i := 0; i < e.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pageID := range pageCh {
				if ctx.Err() != nil {
					return
				}

				// Classify: load first chunk to determine type.
				blocks, err := e.loadFirstChunk(ctx, pageID)
				if err != nil {
					continue
				}
				bv, ok := blocks[pageID]
				if !ok {
					continue
				}

				btype := nStr(bv, "type")
				title := nExtractTitle(bv)

				// Handle databases: collect for Phase 4.
				if btype == "collection_view_page" || btype == "collection_view" || btype == "collection_view_inline" {
					collID := nStr(bv, "collection_id")
					viewIDs := nArr(bv, "view_ids")
					if collID != "" && len(viewIDs) > 0 {
						if vs, ok := viewIDs[0].(string); ok {
							dbMu.Lock()
							databases = append(databases, dbInfo{collID, vs, title})
							dbMu.Unlock()
						}
					}
					continue
				}

				// Handle pages: render and emit.
				if btype != "page" && title == "" {
					continue
				}

				rendered, err := e.renderPage(ctx, pageID)
				if err != nil {
					continue
				}

				// Skip pages with no rendered content and no title.
				if rendered == "" && title == "" {
					continue
				}

				pageURL := fmt.Sprintf("https://www.notion.so/%s", nCleanID(pageID))
				blob := nBuildBlob(title, pageURL, spaceName, rendered)
				blobID := types.ComputeBlobID(blob)
				prov := notionProvenance(pageID, title, pageURL, spaceName)

				callbackMu.Lock()
				cbErr := callback(blob, blobID, prov)
				callbackMu.Unlock()
				if cbErr != nil {
					errOnce.Do(func() { firstErr = cbErr })
					return
				}
				n := scanned.Add(1)
				e.progressf("Scanning pages: %d/%d (%d%%)", n, totalIDs, n*100/int64(totalIDs))
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return firstErr
	}
	e.progressf("Scanning pages: %d/%d (100%%)\n", scanned.Load(), totalIDs)

	// Phase 4: Process databases (serial).
	e.logf("Scanning %d databases...", len(databases))
	for _, db := range databases {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rowIDs, err := e.queryCollection(ctx, db.collectionID, db.viewID)
		if err != nil {
			continue
		}
		for _, rowID := range rowIDs {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			rendered, err := e.renderPage(ctx, rowID)
			if err != nil {
				continue
			}
			pageURL := fmt.Sprintf("https://www.notion.so/%s", nCleanID(rowID))

			rowTitle := ""
			bv, _ := e.loadPageChunkSingle(ctx, rowID)
			if bv != nil {
				rowTitle = nExtractTitle(bv)
			}

			blob := nBuildBlob(rowTitle, pageURL, spaceName, rendered)
			blobID := types.ComputeBlobID(blob)
			prov := notionProvenance(rowID, rowTitle, pageURL, spaceName)

			callbackMu.Lock()
			cbErr := callback(blob, blobID, prov)
			callbackMu.Unlock()
			if cbErr != nil {
				return cbErr
			}
			n := scanned.Add(1)
			e.progressf("Scanning database rows: %d", n-int64(totalIDs))
		}
	}
	if len(databases) > 0 {
		e.progressf("Scanning database rows: done\n")
	}

	return nil
}

// discoverWorkspace calls /getSpaces and returns the workspace ID, name, and
// top-level block IDs (sidebar root pages).
func (e *NotionEnumerator) discoverWorkspace(ctx context.Context) (string, string, []string, error) {
	body, err := e.nPost(ctx, "/getSpaces", map[string]interface{}{})
	if err != nil {
		return "", "", nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", nil, fmt.Errorf("parsing getSpaces: %w", err)
	}

	type workspaceCandidate struct {
		spaceID     string
		name        string
		topBlockIDs []string
	}
	var candidates []workspaceCandidate

	for _, userData := range result {
		userMap, ok := userData.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract top-level block IDs from the block recordMap.
		var topBlockIDs []string
		blockMap := nRaw(userMap, "block")
		if bm, ok := blockMap.(map[string]interface{}); ok {
			for blockID, blockData := range bm {
				bv := nBlockValue(blockData)
				if bv == nil {
					continue
				}
				btype := nStr(bv, "type")
				if btype == "page" || btype == "collection_view_page" ||
					btype == "collection_view" || btype == "collection_view_inline" {
					topBlockIDs = append(topBlockIDs, blockID)
				}
			}
		}

		// Extract private pages from space_view.
		svMap := nRaw(userMap, "space_view")
		if svm, ok := svMap.(map[string]interface{}); ok {
			for _, svData := range svm {
				svValue := nBlockValue(svData)
				if svValue == nil {
					continue
				}
				if pp := nArr(svValue, "private_pages"); pp != nil {
					for _, p := range pp {
						if pid, ok := p.(string); ok {
							topBlockIDs = append(topBlockIDs, pid)
						}
					}
				}
			}
		}

		// Extract space ID and name.
		spaceMap := nRaw(userMap, "space")
		if spaceMap == nil {
			continue
		}
		spaces, ok := spaceMap.(map[string]interface{})
		if !ok {
			continue
		}
		for spaceID, spaceData := range spaces {
			sv := nBlockValue(spaceData)
			if sv == nil {
				continue
			}
			name := nStr(sv, "name")
			if name == "" {
				name = "Untitled Workspace"
			}
			// Workspace filter: skip spaces that don't match.
			if e.config.Workspace != "" {
				if !strings.EqualFold(name, e.config.Workspace) && spaceID != e.config.Workspace {
					continue
				}
			}
			// Also extract workspace-level root pages (teamspace roots).
			blocksCopy := make([]string, len(topBlockIDs))
			copy(blocksCopy, topBlockIDs)
			if pagesArr := nArr(sv, "pages"); pagesArr != nil {
				for _, p := range pagesArr {
					if pid, ok := p.(string); ok {
						blocksCopy = append(blocksCopy, pid)
					}
				}
			}
			candidates = append(candidates, workspaceCandidate{spaceID, name, blocksCopy})
		}
	}

	if len(candidates) == 0 {
		return "", "", nil, fmt.Errorf("no workspace found")
	}
	if len(candidates) > 1 && e.config.Workspace == "" {
		var names []string
		for _, c := range candidates {
			names = append(names, fmt.Sprintf("%s (id: %s)", c.name, c.spaceID))
		}
		sort.Strings(names)
		return "", "", nil, fmt.Errorf("multiple workspaces found, use --workspace to select one: %s", strings.Join(names, ", "))
	}
	return candidates[0].spaceID, candidates[0].name, candidates[0].topBlockIDs, nil
}

// getTeams returns a map of team ID -> team name for the workspace.
func (e *NotionEnumerator) getTeams(ctx context.Context, spaceID string) (map[string]string, error) {
	body, err := e.nPost(ctx, "/getTeams", map[string]interface{}{
		"spaceId": spaceID,
	})
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	teams := make(map[string]string)
	recordMap, _ := result["recordMap"].(map[string]interface{})
	if recordMap == nil {
		return teams, nil
	}
	teamMap, _ := recordMap["team"].(map[string]interface{})
	for tid, t := range teamMap {
		tv, _ := t.(map[string]interface{})
		if tv == nil {
			continue
		}
		v := tv
		if inner, ok := v["value"].(map[string]interface{}); ok {
			v = inner
		}
		if inner, ok := v["value"].(map[string]interface{}); ok {
			v = inner
		}
		name, _ := v["name"].(string)
		if name != "" {
			teams[tid] = name
		}
	}
	return teams, nil
}

// resolveTeamID resolves a teamspace name or ID to a team ID.
func (e *NotionEnumerator) resolveTeamID(ctx context.Context, spaceID, teamspace string) (string, string, error) {
	teams, err := e.getTeams(ctx, spaceID)
	if err != nil {
		return "", "", fmt.Errorf("listing teams: %w", err)
	}

	// Check if it's a direct team ID.
	if name, ok := teams[teamspace]; ok {
		return teamspace, name, nil
	}

	// Try matching by name (case-insensitive).
	lower := strings.ToLower(teamspace)
	for tid, name := range teams {
		if strings.ToLower(name) == lower {
			return tid, name, nil
		}
	}

	// List available teams in error.
	var available []string
	for _, name := range teams {
		available = append(available, name)
	}
	sort.Strings(available)
	return "", "", fmt.Errorf("teamspace %q not found; available: %s", teamspace, strings.Join(available, ", "))
}

// searchBlockIDs calls the Notion /search endpoint to discover block IDs for
// shared and team pages that may not be reachable from the user's sidebar roots.
func (e *NotionEnumerator) searchBlockIDs(ctx context.Context, spaceID string, teamID string) ([]string, error) {
	inTeams := []interface{}{}
	if teamID != "" {
		inTeams = []interface{}{teamID}
	}

	payload := map[string]interface{}{
		"type":    "BlocksInSpace",
		"query":   "",
		"spaceId": spaceID,
		"limit":   1000,
		"filters": map[string]interface{}{
			"isDeletedOnly":             false,
			"excludeTemplates":          false,
			"navigableBlockContentOnly": true,
			"requireEditPermissions":    false,
			"inTeams":                   inTeams,
			"ancestors":                 []interface{}{},
			"createdBy":                 []interface{}{},
			"editedBy":                  []interface{}{},
			"lastEditedTime":            map[string]interface{}{},
			"createdTime":               map[string]interface{}{},
		},
		"sort":   map[string]interface{}{"field": "relevance"},
		"source": "quick_find_input_change",
	}

	body, err := e.nPost(ctx, "/search", payload)
	if err != nil {
		return nil, fmt.Errorf("notion search: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing search response: %w", err)
	}

	var ids []string
	results, _ := result["results"].([]interface{})
	for _, r := range results {
		rm, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if id, _ := rm["id"].(string); id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// nPost sends a POST to the Notion internal API with rate limiting and bounded retry.
// The rate limiter throttles all goroutines to ~RateLimit req/sec total. On 429s
// it backs off for 3 seconds before retrying. Network errors are retried up to 3 times.
func (e *NotionEnumerator) nPost(ctx context.Context, endpoint string, payload interface{}) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}

	for attempt := 0; attempt < 3; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, notionAPIBase+endpoint, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", "token_v2="+e.config.Token)

		resp, err := e.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue // network error, retry
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode == 429 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(3 * time.Second):
			}
			continue
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("notion API %s returned %d", endpoint, resp.StatusCode)
		}

		return body, nil
	}

	return nil, fmt.Errorf("notion API %s failed after 3 attempts", endpoint)
}

// loadPageChunkSingle loads a single page chunk and returns the block value for the given ID.
func (e *NotionEnumerator) loadPageChunkSingle(ctx context.Context, pageID string) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"pageId":          pageID,
		"limit":           100,
		"cursor":          map[string]interface{}{"stack": []interface{}{}},
		"chunkNumber":     0,
		"verticalColumns": false,
	}

	body, err := e.nPost(ctx, "/loadPageChunk", payload)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing loadPageChunk: %w", err)
	}

	recordMap, _ := result["recordMap"].(map[string]interface{})
	if recordMap == nil {
		return nil, nil
	}

	blockMap, _ := recordMap["block"].(map[string]interface{})
	if blockMap == nil {
		return nil, nil
	}

	record, ok := blockMap[pageID]
	if !ok {
		return nil, nil
	}

	return nBlockValue(record), nil
}

// loadFirstChunk loads just the first chunk of a page, returning all block values from the recordMap.
// This is faster than loadAllBlockValues for discovery since we only need to identify child page types.
func (e *NotionEnumerator) loadFirstChunk(ctx context.Context, pageID string) (map[string]map[string]interface{}, error) {
	payload := map[string]interface{}{
		"pageId":          pageID,
		"limit":           100,
		"cursor":          map[string]interface{}{"stack": []interface{}{}},
		"chunkNumber":     0,
		"verticalColumns": false,
	}

	body, err := e.nPost(ctx, "/loadPageChunk", payload)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	blocks := make(map[string]map[string]interface{})
	recordMap, _ := result["recordMap"].(map[string]interface{})
	if recordMap == nil {
		return blocks, nil
	}
	blockMap, _ := recordMap["block"].(map[string]interface{})
	for id, record := range blockMap {
		bv := nBlockValue(record)
		if bv != nil {
			blocks[id] = bv
		}
	}
	return blocks, nil
}

// loadAllBlockValues loads a page and returns all block values from the recordMap.
func (e *NotionEnumerator) loadAllBlockValues(ctx context.Context, pageID string) (map[string]map[string]interface{}, error) {
	allBlocks := make(map[string]map[string]interface{})
	cursor := map[string]interface{}{"stack": []interface{}{}}
	chunkNumber := 0

	for {
		payload := map[string]interface{}{
			"pageId":          pageID,
			"limit":           100,
			"cursor":          cursor,
			"chunkNumber":     chunkNumber,
			"verticalColumns": false,
		}

		body, err := e.nPost(ctx, "/loadPageChunk", payload)
		if err != nil {
			return allBlocks, err
		}

		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			return allBlocks, fmt.Errorf("parsing loadPageChunk: %w", err)
		}

		recordMap, _ := result["recordMap"].(map[string]interface{})
		if recordMap == nil {
			break
		}

		blockMap, _ := recordMap["block"].(map[string]interface{})
		for id, record := range blockMap {
			bv := nBlockValue(record)
			if bv != nil {
				allBlocks[id] = bv
			}
		}

		// Check if we need to paginate.
		newCursor, _ := result["cursor"].(map[string]interface{})
		if newCursor == nil {
			break
		}
		stack, _ := newCursor["stack"].([]interface{})
		if len(stack) == 0 {
			break
		}

		cursor = newCursor
		chunkNumber++
	}

	return allBlocks, nil
}

// queryCollection dumps all row IDs from a database collection.
func (e *NotionEnumerator) queryCollection(ctx context.Context, collectionID, viewID string) ([]string, error) {
	payload := map[string]interface{}{
		"collection": map[string]interface{}{
			"id": collectionID,
		},
		"collectionView": map[string]interface{}{
			"id": viewID,
		},
		"loader": map[string]interface{}{
			"type": "reducer",
			"reducers": map[string]interface{}{
				"collection_group_results": map[string]interface{}{
					"type":  "results",
					"limit": 9999,
				},
			},
			"searchQuery":  "",
			"userTimeZone": "America/Chicago",
		},
	}

	body, err := e.nPost(ctx, "/queryCollection", payload)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing queryCollection: %w", err)
	}

	// Navigate: result.reducerResults.collection_group_results.blockIds
	rr, _ := result["result"].(map[string]interface{})
	if rr == nil {
		return nil, nil
	}
	reducerResults, _ := rr["reducerResults"].(map[string]interface{})
	if reducerResults == nil {
		return nil, nil
	}
	cgr, _ := reducerResults["collection_group_results"].(map[string]interface{})
	if cgr == nil {
		return nil, nil
	}
	rawIDs, _ := cgr["blockIds"].([]interface{})

	var ids []string
	for _, raw := range rawIDs {
		switch v := raw.(type) {
		case string:
			ids = append(ids, v)
		case map[string]interface{}:
			if id, ok := v["id"].(string); ok {
				ids = append(ids, id)
			}
		}
	}

	return ids, nil
}

// renderPage loads all blocks for a page and renders them as text.
func (e *NotionEnumerator) renderPage(ctx context.Context, pageID string) (string, error) {
	blocks, err := e.loadAllBlockValues(ctx, pageID)
	if err != nil {
		return "", err
	}

	root, ok := blocks[pageID]
	if !ok {
		return "", nil
	}

	childIDs := nArr(root, "content")
	return nRenderBlocks(blocks, childIDs, 0), nil
}

// parseNotionPageID extracts a page ID from a Notion URL or raw ID.
// Accepts formats:
//   - 37da484a-7dc4-80dd-936b-d247d86f7ef7 (raw UUID)
//   - 37da484a7dc480dd936bd247d86f7ef7 (no dashes)
//   - https://www.notion.so/Page-Title-37da484a7dc480dd936bd247d86f7ef7
//   - https://app.notion.com/p/Page-Title-37da484a7dc480dd936bd247d86f7ef7?params...
func parseNotionPageID(input string) string {
	// Strip query params
	if idx := strings.Index(input, "?"); idx != -1 {
		input = input[:idx]
	}
	// Take the last path segment
	if strings.Contains(input, "/") {
		parts := strings.Split(input, "/")
		input = parts[len(parts)-1]
	}
	// The ID is the last 32 hex chars (no dashes) of the segment
	clean := strings.ReplaceAll(input, "-", "")
	if len(clean) >= 32 {
		hex := clean[len(clean)-32:]
		// Validate it's hex
		for _, c := range hex {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return input // not hex, return as-is
			}
		}
		// Format as UUID with dashes
		return fmt.Sprintf("%s-%s-%s-%s-%s", hex[0:8], hex[8:12], hex[12:16], hex[16:20], hex[20:32])
	}
	return input
}

// --- Helper functions (n-prefixed to avoid name collisions) ---

// nRaw gets a raw value from a map by key.
func nRaw(m map[string]interface{}, key string) interface{} {
	if m == nil {
		return nil
	}
	return m[key]
}

// nArr gets a slice value from a map by key.
func nArr(m map[string]interface{}, key string) []interface{} {
	if m == nil {
		return nil
	}
	arr, _ := m[key].([]interface{})
	return arr
}

// nStr gets a string value from a map by key.
func nStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// nBlockValue extracts the double-nested value from a Notion record.
// Internal API returns record["value"]["value"] for the actual block data.
func nBlockValue(record interface{}) map[string]interface{} {
	rm, ok := record.(map[string]interface{})
	if !ok {
		return nil
	}

	outer, ok := rm["value"]
	if !ok {
		return nil
	}

	// Try double-nested first: record["value"]["value"]
	if outerMap, ok := outer.(map[string]interface{}); ok {
		if inner, ok := outerMap["value"]; ok {
			if innerMap, ok := inner.(map[string]interface{}); ok {
				return innerMap
			}
		}
		// Fallback: record["value"] is the block data directly.
		return outerMap
	}

	return nil
}

// nExtractTitle extracts the title from a block's properties.
func nExtractTitle(bv map[string]interface{}) string {
	props, ok := bv["properties"].(map[string]interface{})
	if !ok {
		return ""
	}

	titleArr, ok := props["title"].([]interface{})
	if !ok {
		return ""
	}

	var parts []string
	for _, segment := range titleArr {
		seg, ok := segment.([]interface{})
		if !ok || len(seg) == 0 {
			continue
		}
		text, ok := seg[0].(string)
		if ok {
			parts = append(parts, text)
		}
	}

	return strings.Join(parts, "")
}

// nBlockText extracts the text content from a block's properties.
func nBlockText(bv map[string]interface{}) string {
	return nExtractTitle(bv)
}

// nRenderBlocks recursively renders block children as text.
func nRenderBlocks(blocks map[string]map[string]interface{}, childIDs []interface{}, depth int) string {
	var sb strings.Builder
	indent := strings.Repeat("  ", depth)

	for _, cidRaw := range childIDs {
		cid, ok := cidRaw.(string)
		if !ok {
			continue
		}

		bv, ok := blocks[cid]
		if !ok {
			continue
		}

		alive, _ := bv["alive"].(bool)
		if !alive {
			continue
		}

		bt := nStr(bv, "type")
		text := nBlockText(bv)

		switch bt {
		case "header":
			sb.WriteString("# " + text + "\n")
		case "sub_header":
			sb.WriteString("## " + text + "\n")
		case "sub_sub_header":
			sb.WriteString("### " + text + "\n")
		case "text", "":
			if text != "" {
				sb.WriteString(indent + text + "\n")
			}
		case "bulleted_list":
			sb.WriteString(indent + "- " + text + "\n")
		case "numbered_list":
			sb.WriteString(indent + "1. " + text + "\n")
		case "to_do":
			sb.WriteString(indent + "[ ] " + text + "\n")
		case "code":
			sb.WriteString(indent + "```\n" + indent + text + "\n" + indent + "```\n")
		case "quote":
			sb.WriteString(indent + "> " + text + "\n")
		case "callout":
			sb.WriteString(indent + "> " + text + "\n")
		case "toggle":
			sb.WriteString(indent + "▶ " + text + "\n")
		case "divider":
			sb.WriteString("---\n")
		case "bookmark":
			sb.WriteString(indent + "[bookmark] " + text + "\n")
		case "image", "embed", "file":
			src := nStr(bv, "source")
			if src == "" {
				props, _ := bv["properties"].(map[string]interface{})
				if props != nil {
					srcArr, _ := props["source"].([]interface{})
					if len(srcArr) > 0 {
						if seg, ok := srcArr[0].([]interface{}); ok && len(seg) > 0 {
							src, _ = seg[0].(string)
						}
					}
				}
			}
			sb.WriteString(indent + fmt.Sprintf("[%s: %s]\n", bt, src))
		case "page":
			sb.WriteString(indent + "📄 " + text + "\n")
		default:
			if text != "" {
				sb.WriteString(indent + text + "\n")
			}
		}

		subChildren := nArr(bv, "content")
		if len(subChildren) > 0 {
			sb.WriteString(nRenderBlocks(blocks, subChildren, depth+1))
		}
	}

	return sb.String()
}

// nBuildBlob assembles a page blob with metadata header and rendered content.
func nBuildBlob(title, url, spaceName, rendered string) []byte {
	var sb strings.Builder
	sb.WriteString("Title: " + title + "\n")
	sb.WriteString("URL: " + url + "\n")
	sb.WriteString("Space: " + spaceName + "\n")
	sb.WriteString("---\n")
	sb.WriteString(rendered)
	return []byte(sb.String())
}

// nCleanID removes dashes from a Notion UUID for URL construction.
func nCleanID(id string) string {
	return strings.ReplaceAll(id, "-", "")
}
