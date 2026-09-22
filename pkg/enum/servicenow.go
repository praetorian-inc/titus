package enum

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/titus/pkg/types"
)

var snDefaultTables = []string{"incident", "change_request", "kb_knowledge"}

// ServiceNowConfig configures the ServiceNow instance enumerator.
type ServiceNowConfig struct {
	Instance          string    // instance URL (e.g., https://mycompany.service-now.com)
	Username          string    // basic auth username
	Password          string    // basic auth password
	OAuthToken        string    // OAuth2 bearer token (alternative to basic auth)
	Tables            []string  // tables to scan (default: incident, change_request, kb_knowledge)
	RateLimit         float64   // requests per second (default 3)
	AllowInsecureHTTP bool      // allow plaintext HTTP instance URLs
	Verbose           io.Writer // progress output (nil = silent)
}

// ServiceNowEnumerator enumerates blobs from a ServiceNow instance via the REST Table API.
type ServiceNowEnumerator struct {
	config  ServiceNowConfig
	client  *http.Client
	limiter *rate.Limiter
	apiBase string
}

// NewServiceNowEnumerator creates a new ServiceNow enumerator.
func NewServiceNowEnumerator(cfg ServiceNowConfig) (*ServiceNowEnumerator, error) {
	if cfg.Instance == "" {
		return nil, fmt.Errorf("servicenow instance URL is required")
	}
	if cfg.OAuthToken == "" && (cfg.Username == "" || cfg.Password == "") {
		return nil, fmt.Errorf("servicenow auth required: provide --username + --password, or --oauth-token")
	}

	insecure, err := ValidateBaseURL(cfg.Instance)
	if err != nil {
		return nil, fmt.Errorf("servicenow instance URL: %w", err)
	}
	if insecure && !cfg.AllowInsecureHTTP {
		return nil, fmt.Errorf("servicenow instance URL uses plaintext HTTP, which exposes credentials; use HTTPS or set AllowInsecureHTTP")
	}

	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 3.0
	}
	if len(cfg.Tables) == 0 {
		cfg.Tables = snDefaultTables
	}

	apiBase := strings.TrimRight(cfg.Instance, "/") + "/api/now/table"

	return &ServiceNowEnumerator{
		config:  cfg,
		client:  &http.Client{Timeout: 30 * time.Second},
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
		apiBase: apiBase,
	}, nil
}

func snProvenance(table, sysID, number, shortDesc, recordURL string) types.ExtendedProvenance {
	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":     "servicenow",
			"entityType": table,
			"identifier": sysID,
			"number":     number,
			"title":      shortDesc,
			"url":        recordURL,
			"path":       recordURL,
		},
	}
}

func (e *ServiceNowEnumerator) logf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, format+"\n", args...)
	}
}

func (e *ServiceNowEnumerator) progressf(format string, args ...interface{}) {
	if e.config.Verbose != nil {
		_, _ = fmt.Fprintf(e.config.Verbose, "\r%-80s", fmt.Sprintf(format, args...))
	}
}

// snRecord holds the fields we extract from each ServiceNow table record.
type snRecord struct {
	SysID            string `json:"sys_id"`
	Number           string `json:"number"`
	ShortDescription string `json:"short_description"`
	Description      string `json:"description"`
	WorkNotes        string `json:"work_notes"`
	Comments         string `json:"comments"`
	// KB articles use different field names.
	Text string `json:"text"`
}

// snTableResponse is the envelope returned by the Table API.
type snTableResponse struct {
	Result json.RawMessage `json:"result"`
}

// snGet performs a rate-limited GET with auth and retry.
func (e *ServiceNowEnumerator) snGet(ctx context.Context, reqURL string) ([]byte, error) {
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := e.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}

		if e.config.OAuthToken != "" {
			req.Header.Set("Authorization", "Bearer "+e.config.OAuthToken)
		} else {
			encoded := base64.StdEncoding.EncodeToString([]byte(e.config.Username + ":" + e.config.Password))
			req.Header.Set("Authorization", "Basic "+encoded)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := e.client.Do(req)
		if err != nil {
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return nil, fmt.Errorf("http request: %w", err)
		}

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			_ = resp.Body.Close()
			if attempt < maxAttempts-1 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(2 * time.Second):
				}
				continue
			}
			return nil, fmt.Errorf("servicenow API returned %d after %d attempts", resp.StatusCode, maxAttempts)
		}

		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("servicenow API returned unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
		return body, nil
	}
	return nil, fmt.Errorf("snGet: exceeded max attempts")
}

// snFetchRecords retrieves all records from a table using offset pagination.
func (e *ServiceNowEnumerator) snFetchRecords(ctx context.Context, table string) ([]snRecord, error) {
	var all []snRecord
	offset := 0
	limit := 100
	for {
		reqURL := fmt.Sprintf("%s/%s?sysparm_limit=%d&sysparm_offset=%d&sysparm_fields=%s",
			e.apiBase, url.PathEscape(table), limit, offset,
			"sys_id,number,short_description,description,work_notes,comments,text")

		body, err := e.snGet(ctx, reqURL)
		if err != nil {
			return nil, fmt.Errorf("fetch %s records: %w", table, err)
		}

		var resp snTableResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode %s response: %w", table, err)
		}

		var records []snRecord
		if err := json.Unmarshal(resp.Result, &records); err != nil {
			return nil, fmt.Errorf("decode %s records: %w", table, err)
		}

		all = append(all, records...)

		if len(records) < limit {
			break
		}
		offset += limit
	}
	return all, nil
}

// snBuildRecordBlob assembles a ServiceNow record into a single blob for scanning.
func snBuildRecordBlob(table string, rec snRecord, instanceURL string) []byte {
	var sb strings.Builder
	sb.WriteString("Table: " + table + "\n")
	if rec.Number != "" {
		sb.WriteString("Number: " + rec.Number + "\n")
	}
	if rec.ShortDescription != "" {
		sb.WriteString("Short Description: " + rec.ShortDescription + "\n")
	}
	recordURL := strings.TrimRight(instanceURL, "/") + "/" + table + ".do?sys_id=" + rec.SysID
	sb.WriteString("URL: " + recordURL + "\n")
	sb.WriteString("---\n")

	if rec.Description != "" {
		sb.WriteString(rec.Description + "\n")
	}
	if rec.Text != "" {
		sb.WriteString(rec.Text + "\n")
	}
	if rec.WorkNotes != "" {
		sb.WriteString("\n--- Work Notes ---\n")
		sb.WriteString(rec.WorkNotes + "\n")
	}
	if rec.Comments != "" {
		sb.WriteString("\n--- Comments ---\n")
		sb.WriteString(rec.Comments + "\n")
	}
	return []byte(sb.String())
}

// Enumerate discovers content from a ServiceNow instance and yields blobs.
func (e *ServiceNowEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	e.logf("Scanning %d tables: %s", len(e.config.Tables), strings.Join(e.config.Tables, ", "))

	var count atomic.Int64
	var errs []string

	for _, table := range e.config.Tables {
		records, err := e.snFetchRecords(ctx, table)
		if err != nil {
			errs = append(errs, fmt.Sprintf("table %s: %v", table, err))
			continue
		}

		e.logf("Table %s: %d records", table, len(records))

		for _, rec := range records {
			blob := snBuildRecordBlob(table, rec, e.config.Instance)
			blobID := types.ComputeBlobID(blob)
			recordURL := strings.TrimRight(e.config.Instance, "/") + "/" + table + ".do?sys_id=" + rec.SysID
			prov := snProvenance(table, rec.SysID, rec.Number, rec.ShortDescription, recordURL)

			n := count.Add(1)
			e.progressf("Scanning records: %d", n)

			if err := callback(blob, blobID, prov); err != nil {
				return err
			}
		}
	}

	e.logf("Scanned %d records across %d tables", count.Load(), len(e.config.Tables))

	if len(errs) > 0 {
		return fmt.Errorf("enumeration errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
