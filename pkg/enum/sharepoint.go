package enum

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/titus/pkg/types"
)

const spGraphBase = "https://graph.microsoft.com/v1.0"

var (
	spHTMLTagRe = regexp.MustCompile(`<[^>]*>`)

	// spSkipExtensions are file types that can't produce useful text for secrets scanning.
	spSkipExtensions = map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true,
		".ico": true, ".svg": true, ".webp": true, ".tiff": true, ".tif": true,
		".mp4": true, ".avi": true, ".mov": true, ".wmv": true, ".mkv": true,
		".mp3": true, ".wav": true, ".flac": true, ".aac": true, ".ogg": true,
		".iso": true, ".dmg": true, ".exe": true, ".dll": true, ".so": true,
		".dylib": true, ".msi": true, ".deb": true, ".rpm": true,
		".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	}
)

// spStripHTML removes HTML tags and unescapes HTML entities.
func spStripHTML(s string) string {
	stripped := spHTMLTagRe.ReplaceAllString(s, "")
	return html.UnescapeString(stripped)
}

// spSkipFile returns true if the file extension indicates a binary type
// that cannot produce useful text for secrets scanning.
func spSkipFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return spSkipExtensions[ext]
}

// SharePointConfig configures the SharePoint enumerator.
type SharePointConfig struct {
	Token   string    // OAuth bearer token for Microsoft Graph API
	Site    string    // specific site URL or name to scan (empty = all sites)
	Verbose io.Writer // progress output
}

// SharePointEnumerator enumerates blobs from SharePoint via the Microsoft Graph API.
type SharePointEnumerator struct {
	config SharePointConfig
	client *http.Client
}

// NewSharePointEnumerator creates a new SharePoint enumerator.
func NewSharePointEnumerator(cfg SharePointConfig) (*SharePointEnumerator, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("sharepoint requires --token (OAuth bearer token for Graph API)")
	}
	return &SharePointEnumerator{
		config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// logf writes a progress message when verbose output is enabled.
func (e *SharePointEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s\n", fmt.Sprintf(format, args...))
	}
}

// progressf writes an in-place progress update (no trailing newline) using \r.
func (e *SharePointEnumerator) progressf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s", fmt.Sprintf(format, args...))
	}
}

// spProvenance builds an ExtendedProvenance for a SharePoint item.
func spProvenance(site, path, title, url string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source": "sharepoint",
			"site":   site,
			"path":   path,
			"title":  title,
			"url":    url,
		},
	}
}

// spGet performs an HTTP GET with retry logic for 429 and 503 responses.
func (e *SharePointEnumerator) spGet(ctx context.Context, url string) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+e.config.Token)
		req.Header.Set("User-Agent", "NONISV|Praetorian|Titus/1.0")

		resp, err := e.client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode == 429 {
			wait := 3 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil {
					wait = time.Duration(secs) * time.Second
				}
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		if resp.StatusCode == 503 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("sharepoint API %s returned %d: %s", url, resp.StatusCode, string(body))
		}

		return body, nil
	}

	return nil, fmt.Errorf("sharepoint API %s failed after 3 attempts", url)
}

// spGetPaginated fetches all pages of a Graph API list endpoint.
// Returns the concatenated "value" arrays from all pages.
func (e *SharePointEnumerator) spGetPaginated(ctx context.Context, url string) ([]map[string]interface{}, error) {
	var all []map[string]interface{}
	for url != "" {
		body, err := e.spGet(ctx, url)
		if err != nil {
			return all, err
		}
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			return all, fmt.Errorf("parsing response: %w", err)
		}
		values, _ := result["value"].([]interface{})
		for _, v := range values {
			if m, ok := v.(map[string]interface{}); ok {
				all = append(all, m)
			}
		}
		nextLink, _ := result["@odata.nextLink"].(string)
		url = nextLink
	}
	return all, nil
}

// Enumerate discovers SharePoint content and yields blobs to the callback.
func (e *SharePointEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Phase 1: Discover sites.
	sites, err := e.discoverSites(ctx)
	if err != nil {
		return fmt.Errorf("discovering sites: %w", err)
	}
	e.logf("Discovered %d sites", len(sites))

	// Phase 2 & 3: For each site, discover and emit content.
	for i, site := range sites {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		siteID, _ := site["id"].(string)
		siteName, _ := site["displayName"].(string)
		siteURL, _ := site["webUrl"].(string)
		if siteName == "" {
			siteName, _ = site["name"].(string)
		}

		e.logf("Scanning site %d/%d: %s", i+1, len(sites), siteName)

		// 2a. Document library files.
		if err := e.scanDrives(ctx, siteID, siteName, siteURL, callback); err != nil {
			e.logf("Warning: scanning drives for site %s: %v", siteName, err)
		}

		// 2b. SharePoint pages.
		if err := e.scanPages(ctx, siteID, siteName, siteURL, callback); err != nil {
			e.logf("Warning: scanning pages for site %s: %v", siteName, err)
		}

		// 2c. List items.
		if err := e.scanLists(ctx, siteID, siteName, siteURL, callback); err != nil {
			e.logf("Warning: scanning lists for site %s: %v", siteName, err)
		}
	}

	return nil
}

// discoverSites finds SharePoint sites to scan.
func (e *SharePointEnumerator) discoverSites(ctx context.Context) ([]map[string]interface{}, error) {
	if e.config.Site != "" {
		// Resolve specific site.
		site := e.config.Site

		// Try direct lookup if it looks like a URL with /sites/ path.
		if strings.Contains(site, "/sites/") {
			// Extract hostname and path from URL.
			site = strings.TrimPrefix(site, "https://")
			site = strings.TrimPrefix(site, "http://")
			parts := strings.SplitN(site, "/sites/", 2)
			if len(parts) == 2 {
				hostname := parts[0]
				sitePath := strings.TrimRight(parts[1], "/")
				url := fmt.Sprintf("%s/sites/%s:/sites/%s", spGraphBase, hostname, sitePath)
				body, err := e.spGet(ctx, url)
				if err != nil {
					// Fall back to search.
					return e.searchSites(ctx, e.config.Site)
				}
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err != nil {
					return e.searchSites(ctx, e.config.Site)
				}
				return []map[string]interface{}{result}, nil
			}
		}

		// Search for the site by name.
		return e.searchSites(ctx, site)
	}

	// Enumerate all sites.
	return e.spGetPaginated(ctx, spGraphBase+"/sites?search=*")
}

// searchSites searches for sites matching a query.
func (e *SharePointEnumerator) searchSites(ctx context.Context, query string) ([]map[string]interface{}, error) {
	searchURL := fmt.Sprintf("%s/sites?search=%s", spGraphBase, url.QueryEscape(query))
	return e.spGetPaginated(ctx, searchURL)
}

// scanDrives scans document libraries for text-scannable files.
func (e *SharePointEnumerator) scanDrives(ctx context.Context, siteID, siteName, siteURL string, callback func([]byte, types.BlobID, types.Provenance) error) error {
	drives, err := e.spGetPaginated(ctx, fmt.Sprintf("%s/sites/%s/drives", spGraphBase, siteID))
	if err != nil {
		return err
	}
	e.logf("  Found %d drives", len(drives))

	for _, drive := range drives {
		driveID, _ := drive["id"].(string)
		if driveID == "" {
			continue
		}
		driveName, _ := drive["name"].(string)
		e.logf("  Drive: %s", driveName)

		err := e.walkDriveFolder(ctx, driveID, "", siteName, siteURL, callback)
		if err != nil {
			e.logf("Warning: walking drive %s: %v", driveID, err)
		}
	}

	return nil
}

// walkDriveFolder recursively walks a drive folder, downloading text files.
func (e *SharePointEnumerator) walkDriveFolder(ctx context.Context, driveID, folderID, siteName, siteURL string, callback func([]byte, types.BlobID, types.Provenance) error) error {
	var url string
	if folderID == "" {
		url = fmt.Sprintf("%s/drives/%s/root/children", spGraphBase, driveID)
	} else {
		url = fmt.Sprintf("%s/drives/%s/items/%s/children", spGraphBase, driveID, folderID)
	}

	items, err := e.spGetPaginated(ctx, url)
	if err != nil {
		return err
	}

	if folderID == "" {
		fileCount := 0
		folderCount := 0
		for _, it := range items {
			if _, isFolder := it["folder"]; isFolder {
				folderCount++
			} else {
				fileCount++
			}
		}
		e.logf("    Root: %d files, %d folders", fileCount, folderCount)
	}

	for _, item := range items {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		name, _ := item["name"].(string)
		itemID, _ := item["id"].(string)

		// Check if it's a folder.
		if _, isFolder := item["folder"]; isFolder {
			if err := e.walkDriveFolder(ctx, driveID, itemID, siteName, siteURL, callback); err != nil {
				e.logf("Warning: walking folder %s: %v", name, err)
			}
			continue
		}

		// Skip files we can't extract useful text from.
		if spSkipFile(name) {
			continue
		}

		// Check file size (skip over 100MB — extraction limits handle per-file caps).
		if size, ok := item["size"].(float64); ok && size > 100*1024*1024 {
			continue
		}

		// Build file path from parentReference.
		filePath := name
		if parentRef, ok := item["parentReference"].(map[string]interface{}); ok {
			if p, ok := parentRef["path"].(string); ok {
				filePath = p + "/" + name
			}
		}

		// Download file content.
		downloadURL := fmt.Sprintf("%s/drives/%s/items/%s/content", spGraphBase, driveID, itemID)
		content, err := e.spGet(ctx, downloadURL)
		if err != nil {
			e.logf("Warning: downloading %s: %v", name, err)
			continue
		}

		fileURL := siteURL
		if webURL, ok := item["webUrl"].(string); ok {
			fileURL = webURL
		}

		if isBinary(content) {
			// Extract text from binary files (Office docs, PDFs, archives, etc.)
			extracted, err := ExtractText(filePath, content, DefaultExtractionLimits())
			if err != nil || len(extracted) == 0 {
				continue
			}
			for _, ec := range extracted {
				blobID := types.ComputeBlobID(ec.Content)
				extractPath := filePath
				if ec.Name != "" {
					extractPath = filePath + "/" + ec.Name
				}
				prov := spProvenance(siteName, extractPath, name, fileURL)
				if err := callback(ec.Content, blobID, prov); err != nil {
					return err
				}
			}
		} else {
			blobID := types.ComputeBlobID(content)
			prov := spProvenance(siteName, filePath, name, fileURL)
			if err := callback(content, blobID, prov); err != nil {
				return err
			}
		}

		e.progressf("Scanning files: %s", name)
	}

	return nil
}

// scanPages scans SharePoint site pages for text content.
func (e *SharePointEnumerator) scanPages(ctx context.Context, siteID, siteName, siteURL string, callback func([]byte, types.BlobID, types.Provenance) error) error {
	pages, err := e.spGetPaginated(ctx, fmt.Sprintf("%s/sites/%s/pages/microsoft.graph.sitePage", spGraphBase, siteID))
	if err != nil {
		return err
	}
	e.logf("  Found %d pages", len(pages))

	for _, page := range pages {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		pageID, _ := page["id"].(string)
		pageTitle, _ := page["title"].(string)
		pageURL, _ := page["webUrl"].(string)

		if pageID == "" {
			continue
		}

		// Get page content with canvas layout.
		detailURL := fmt.Sprintf("%s/sites/%s/pages/%s/microsoft.graph.sitePage?$expand=canvasLayout", spGraphBase, siteID, pageID)
		body, err := e.spGet(ctx, detailURL)
		if err != nil {
			e.logf("Warning: fetching page %s: %v", pageTitle, err)
			continue
		}

		var detail map[string]interface{}
		if err := json.Unmarshal(body, &detail); err != nil {
			continue
		}

		// Extract text from canvasLayout.
		text := e.extractCanvasText(detail)
		if text == "" {
			continue
		}

		// Build blob.
		var sb strings.Builder
		sb.WriteString("Title: " + pageTitle + "\n")
		sb.WriteString("URL: " + pageURL + "\n")
		sb.WriteString("Site: " + siteName + "\n")
		sb.WriteString("Type: page\n")
		sb.WriteString("---\n")
		sb.WriteString(text)
		blob := []byte(sb.String())

		blobID := types.ComputeBlobID(blob)
		prov := spProvenance(siteName, "", pageTitle, pageURL)

		if err := callback(blob, blobID, prov); err != nil {
			return err
		}

		e.progressf("Scanning pages: %s", pageTitle)
	}

	return nil
}

// extractCanvasText extracts text content from a page's canvasLayout.
func (e *SharePointEnumerator) extractCanvasText(detail map[string]interface{}) string {
	layout, _ := detail["canvasLayout"].(map[string]interface{})
	if layout == nil {
		return ""
	}

	var parts []string

	sections, _ := layout["horizontalSections"].([]interface{})
	for _, sec := range sections {
		secMap, ok := sec.(map[string]interface{})
		if !ok {
			continue
		}
		columns, _ := secMap["columns"].([]interface{})
		for _, col := range columns {
			colMap, ok := col.(map[string]interface{})
			if !ok {
				continue
			}
			webparts, _ := colMap["webparts"].([]interface{})
			for _, wp := range webparts {
				wpMap, ok := wp.(map[string]interface{})
				if !ok {
					continue
				}
				if innerHTML, ok := wpMap["innerHtml"].(string); ok && innerHTML != "" {
					parts = append(parts, spStripHTML(innerHTML))
				}
			}
		}
	}

	return strings.Join(parts, "\n")
}

// scanLists scans SharePoint lists for item content.
func (e *SharePointEnumerator) scanLists(ctx context.Context, siteID, siteName, siteURL string, callback func([]byte, types.BlobID, types.Provenance) error) error {
	lists, err := e.spGetPaginated(ctx, fmt.Sprintf("%s/sites/%s/lists", spGraphBase, siteID))
	if err != nil {
		return err
	}
	e.logf("  Found %d lists", len(lists))

	for _, list := range lists {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Skip system lists.
		if _, hasSystem := list["system"]; hasSystem {
			continue
		}

		// Skip document libraries (covered by drives).
		if tmpl, ok := list["list"].(map[string]interface{}); ok {
			if template, _ := tmpl["template"].(string); template == "documentLibrary" {
				continue
			}
		}

		listID, _ := list["id"].(string)
		listName, _ := list["displayName"].(string)
		if listID == "" {
			continue
		}

		// Fetch list items with fields.
		items, err := e.spGetPaginated(ctx, fmt.Sprintf("%s/sites/%s/lists/%s/items?expand=fields", spGraphBase, siteID, listID))
		if err != nil {
			e.logf("Warning: fetching list %s items: %v", listName, err)
			continue
		}

		for _, item := range items {
			fields, ok := item["fields"].(map[string]interface{})
			if !ok || len(fields) == 0 {
				continue
			}

			// Render fields as key: value lines (sorted for deterministic blob IDs).
			var sb strings.Builder
			sb.WriteString("List: " + listName + "\n")
			sb.WriteString("Site: " + siteName + "\n")
			sb.WriteString("---\n")

			keys := make([]string, 0, len(fields))
			for k := range fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := fields[k]
				fmt.Fprintf(&sb, "%s: %v\n", k, v)
			}

			blob := []byte(sb.String())
			blobID := types.ComputeBlobID(blob)

			itemTitle := listName
			if t, ok := fields["Title"].(string); ok && t != "" {
				itemTitle = t
			}

			itemURL := siteURL
			if webURL, ok := item["webUrl"].(string); ok {
				itemURL = webURL
			}

			prov := spProvenance(siteName, "", itemTitle, itemURL)

			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}
	}

	return nil
}

