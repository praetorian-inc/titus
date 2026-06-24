package enum

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/time/rate"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/praetorian-inc/titus/pkg/types"
)

// callbackErr wraps an error returned by the caller's callback so that
// listFiles can distinguish infrastructure failures from per-file Drive errors.
type callbackErr struct{ err error }

func (e *callbackErr) Error() string { return e.err.Error() }
func (e *callbackErr) Unwrap() error { return e.err }

const (
	gdriveBaseDelay    = 500 * time.Millisecond
	gdriveFileFields   = "nextPageToken, files(id,name,mimeType,size,owners(emailAddress),webViewLink,driveId,capabilities(canDownload,canCopy))"
	gdriveDriveFields  = "nextPageToken, drives(id,name)"
	gdriveFileListSize = 1000
	gdriveDriveListSize = 100
)

// GDriveScope controls which slice of a user's Drive is enumerated.
type GDriveScope int

const (
	GDriveScopeAll         GDriveScope = iota // my drive + shared-with-me + all shared drives
	GDriveScopeMine                            // only files in My Drive ('me' in owners)
	GDriveScopeSharedWithMe                    // only files shared with me
	GDriveScopeSharedDrives                    // walk every shared drive, no my-drive/shared-with-me pass
	GDriveScopeSingleDrive                     // one specific shared drive (DriveID populated)
)

// GDriveConfig configures Google Drive enumeration.
type GDriveConfig struct {
	Token        string        // OAuth access token (optional if RefreshToken+ClientID+ClientSecret provided)
	RefreshToken string        // OAuth refresh token; enables auto-refresh for long scans
	ClientID     string        // OAuth client ID (required with RefreshToken)
	ClientSecret string        // OAuth client secret (required with RefreshToken)

	Scope   GDriveScope // which slice of Drive to enumerate
	DriveID string      // required when Scope == GDriveScopeSingleDrive

	Verbose io.Writer // progress output (nil = silent)

	RateLimit   float64       // requests per second (default 16)
	MaxRetries  int           // default 6
	MaxBackoff  time.Duration // default 64s
	Concurrency int           // workers processing files; default 5; clamped to [1, 100]

	Config // embedded enum.Config (MaxFileSize, ExtractArchives, ExtractLimits)
}

// GDriveEnumerator enumerates blobs from Google Drive.
type GDriveEnumerator struct {
	svc     *drive.Service
	cfg     GDriveConfig
	limiter *rate.Limiter
	// seen tracks Drive file IDs already yielded so the same file isn't
	// downloaded twice when it appears in multiple list passes (e.g.,
	// shared-with-me + a shared drive).
	seen   map[string]struct{}
	seenMu sync.Mutex
	logMu  sync.Mutex
}

// NewGDriveEnumerator creates a new Google Drive enumerator.
// Provide either cfg.Token (short scans) or cfg.RefreshToken + cfg.ClientID +
// cfg.ClientSecret (long scans; the client refreshes transparently).
func NewGDriveEnumerator(cfg GDriveConfig) (*GDriveEnumerator, error) {
	// Apply defaults
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 16
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 6
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 64 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	if cfg.Concurrency > 100 {
		cfg.Concurrency = 100
	}

	if cfg.Scope == GDriveScopeSingleDrive && cfg.DriveID == "" {
		return nil, fmt.Errorf("gdrive: DriveID is required when Scope is SingleDrive")
	}

	var ts oauth2.TokenSource
	switch {
	case cfg.RefreshToken != "":
		if cfg.ClientID == "" {
			return nil, fmt.Errorf("gdrive: ClientID is required when RefreshToken is provided")
		}
		if cfg.ClientSecret == "" {
			return nil, fmt.Errorf("gdrive: ClientSecret is required when RefreshToken is provided")
		}
		conf := &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     google.Endpoint,
		}
		tok := &oauth2.Token{
			AccessToken:  cfg.Token,
			RefreshToken: cfg.RefreshToken,
			// Force refresh on first use if AccessToken is empty or stale.
			Expiry: time.Now().Add(-time.Second),
		}
		ts = conf.TokenSource(context.Background(), tok)
	case cfg.Token != "":
		ts = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.Token})
	default:
		return nil, fmt.Errorf("gdrive: must provide either Token, or RefreshToken+ClientID+ClientSecret")
	}

	svc, err := drive.NewService(context.Background(), option.WithTokenSource(ts))
	if err != nil {
		return nil, fmt.Errorf("gdrive: creating Drive service: %w", err)
	}

	// Burst must be ≥ 1 for rate.NewLimiter to permit any traffic; for our
	// strictly sequential caller it has no runtime effect beyond that, so
	// derive it directly from the rate.
	burst := int(cfg.RateLimit)
	if burst < 1 {
		burst = 1
	}
	lim := rate.NewLimiter(rate.Limit(cfg.RateLimit), burst)

	return &GDriveEnumerator{
		svc:     svc,
		cfg:     cfg,
		limiter: lim,
		seen:    make(map[string]struct{}),
	}, nil
}

// logf writes a progress message when verbose output is enabled.
func (e *GDriveEnumerator) logf(format string, args ...interface{}) {
	if e.cfg.Verbose != nil {
		e.logMu.Lock()
		_, _ = fmt.Fprintf(e.cfg.Verbose, format+"\n", args...)
		e.logMu.Unlock()
	}
}

// Enumerate walks the portion of Drive indicated by cfg.Scope, yielding each
// scannable file through callback.
func (e *GDriveEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	var cbMu sync.Mutex
	safeCb := func(content []byte, id types.BlobID, prov types.Provenance) error {
		cbMu.Lock()
		defer cbMu.Unlock()
		return callback(content, id, prov)
	}

	switch e.cfg.Scope {
	case GDriveScopeMine:
		return e.listFiles(ctx, `trashed=false and 'me' in owners`, "", "", "", safeCb)

	case GDriveScopeSharedWithMe:
		return e.listFiles(ctx, "sharedWithMe=true and trashed=false", "", "", "", safeCb)

	case GDriveScopeSharedDrives:
		return e.enumerateSharedDrives(ctx, safeCb)

	case GDriveScopeSingleDrive:
		return e.listFiles(ctx, "trashed=false", e.cfg.DriveID, "drive", e.cfg.DriveID, safeCb)

	default: // GDriveScopeAll — preserve existing 3-pass behavior
		// Pass 1: My Drive
		if err := e.listFiles(ctx, `trashed=false and 'me' in owners`, "", "", "", safeCb); err != nil {
			return fmt.Errorf("gdrive: enumerating My Drive: %w", err)
		}

		// Pass 2: Shared with me
		if err := e.listFiles(ctx, "sharedWithMe=true and trashed=false", "", "", "", safeCb); err != nil {
			return fmt.Errorf("gdrive: enumerating Shared-with-me: %w", err)
		}

		// Pass 3: All shared drives
		return e.enumerateSharedDrives(ctx, safeCb)
	}
}

// enumerateSharedDrives lists all shared drives and enumerates each one.
func (e *GDriveEnumerator) enumerateSharedDrives(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	listFn := func(page *drive.DriveList) error {
		for _, d := range page.Drives {
			e.logf("Entering shared drive %q (id=%s)", d.Name, d.Id)
			if err := e.listFiles(ctx, "trashed=false", d.Id, "drive", d.Id, callback); err != nil {
				return fmt.Errorf("enumerating shared drive %q: %w", d.Name, err)
			}
		}
		return nil
	}

	if err := e.limiter.Wait(ctx); err != nil {
		return err
	}
	req := e.svc.Drives.List().PageSize(int64(gdriveDriveListSize)).Fields(gdriveDriveFields).Context(ctx)
	err := e.withRetry(ctx, func() error {
		return req.Pages(ctx, listFn)
	})
	if err != nil {
		return err
	}
	return nil
}

// listFiles paginates a files.list query and processes each file concurrently.
// driveID and driveName are passed through to processFile for provenance.
// corpora selects the search corpus ("drive" for a specific shared drive, "" for My Drive).
// When corpora == "drive", the list call uses IncludeItemsFromAllDrives+SupportsAllDrives.
func (e *GDriveEnumerator) listFiles(ctx context.Context, q, driveID, corpora, driveName string, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	type fileJob struct {
		f *drive.File
	}

	concurrency := e.cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	fileCh := make(chan fileJob, 2*concurrency)

	var firstErr error
	var errOnce sync.Once
	setErr := func(err error) { errOnce.Do(func() { firstErr = err }) }

	// Producer: paginate and send files into fileCh.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(fileCh)

		req := e.svc.Files.List().
			Q(q).
			Spaces("drive").
			PageSize(int64(gdriveFileListSize)).
			Fields(gdriveFileFields).
			Context(ctx)

		if corpora == "drive" && driveID != "" {
			req = req.
				DriveId(driveID).
				Corpora("drive").
				IncludeItemsFromAllDrives(true).
				SupportsAllDrives(true)
		}

		pageErr := e.withRetry(ctx, func() error {
			return req.Pages(ctx, func(page *drive.FileList) error {
				// Each page fetch is a Drive API request; wait for the limiter.
				if err := e.limiter.Wait(ctx); err != nil {
					return err
				}
				for _, f := range page.Files {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if firstErr != nil {
						return firstErr
					}
					select {
					case fileCh <- fileJob{f: f}:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			})
		})
		if pageErr != nil {
			setErr(pageErr)
		}
	}()

	// Workers: process files from fileCh.
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range fileCh {
				if ctx.Err() != nil {
					return
				}
				if firstErr != nil {
					return
				}
				if err := e.processFile(ctx, job.f, driveID, driveName, callback); err != nil {
					if ctx.Err() != nil {
						return
					}
					// Callback errors (datastore/infrastructure) are fatal.
					var ce *callbackErr
					if errors.As(err, &ce) {
						setErr(ce.err)
						return
					}
					// Drive API errors (per-file 403, 404, etc.) are non-fatal: warn and continue.
					e.logf("Warning: gdrive %s: %v", job.f.Id, err)
				}
			}
		}()
	}

	wg.Wait()
	return firstErr
}

// processFile classifies, downloads or exports a single Drive file and emits
// blobs via callback.
func (e *GDriveEnumerator) processFile(ctx context.Context, f *drive.File, driveID, driveName string, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	e.seenMu.Lock()
	if e.seen == nil {
		e.seen = make(map[string]struct{})
	}
	if _, dup := e.seen[f.Id]; dup {
		e.seenMu.Unlock()
		return nil
	}
	e.seen[f.Id] = struct{}{}
	e.seenMu.Unlock()

	action, exportMIME := classifyGDriveMIME(f.MimeType)
	if action == gdriveSkip {
		return nil
	}

	e.logf("Processing %s", f.Name)

	// Capability check — only meaningful for raw downloads. Workspace docs
	// route through files.export, which has its own permission model that
	// is NOT predicted by canDownload OR canCopy in practice; let the export
	// call fly and handle errors in the normal retry/warn path.
	if action == gdriveDownload && f.Capabilities != nil && !f.Capabilities.CanDownload {
		return nil
	}

	// Size check (only meaningful for raw files; exported content size is unknown)
	if e.cfg.MaxFileSize > 0 && f.Size > 0 && f.Size > e.cfg.MaxFileSize {
		return nil
	}

	// User-explicit cap. MaxFileSize=0 means UNLIMITED — user opted in.
	maxRead := e.cfg.MaxFileSize // 0 = unlimited passed through to downloadFile/exportFile

	var content []byte
	var err error

	switch action {
	case gdriveDownload:
		content, err = e.downloadFile(ctx, f.Id, maxRead)
	case gdriveExport:
		content, err = e.exportFile(ctx, f.Id, exportMIME, maxRead)
	}
	if err != nil {
		return err
	}
	if content == nil {
		return nil // oversized or empty
	}

	// extractName is the path used to route extraction by extension. For native
	// Google Sheets we export as xlsx, but the Drive file itself has no extension,
	// so synthesize ".xlsx" so getExtension / extractXLSX can route correctly.
	extractName := f.Name
	if action == gdriveExport && exportMIME == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" {
		extractName += ".xlsx"
	}

	// Build path
	effectiveDriveID := driveID
	if effectiveDriveID == "" {
		effectiveDriveID = f.DriveId // may also be empty for My Drive files
	}
	var gdrivePath string
	if effectiveDriveID != "" {
		gdrivePath = fmt.Sprintf("gdrive://drive/%s/%s", effectiveDriveID, f.Id)
	} else {
		gdrivePath = fmt.Sprintf("gdrive:///%s", f.Id)
	}

	// Owner email
	ownerEmail := ""
	if len(f.Owners) > 0 {
		ownerEmail = f.Owners[0].EmailAddress
	}

	// Binary handling
	if isBinary(content) {
		if e.cfg.ExtractArchives != "" {
			ext := extFromName(extractName)
			if shouldExtract(e.cfg.Config, ext) {
				extracted, extractErr := ExtractText(extractName, content, e.cfg.ExtractLimits)
				if extractErr == nil && len(extracted) > 0 {
					for _, ec := range extracted {
						blobID := types.ComputeBlobID(ec.Content)
						prov := types.ArchiveProvenance{
							ArchivePath: gdrivePath,
							MemberPath:  ec.Name,
						}
						if err := callback(ec.Content, blobID, prov); err != nil {
							return &callbackErr{err: err}
						}
					}
				}
			}
		}
		return nil
	}

	blobID := types.ComputeBlobID(content)
	prov := types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source":        "gdrive",
			"file_id":       f.Id,
			"name":          f.Name,
			"mime_type":     f.MimeType,
			"owner":         ownerEmail,
			"drive_id":      effectiveDriveID,
			"drive_name":    driveName,
			"web_view_link": f.WebViewLink,
			"path":          gdrivePath,
		},
	}

	if err := callback(content, blobID, prov); err != nil {
		return &callbackErr{err: err}
	}
	return nil
}

// downloadFile downloads a raw file body, capped at maxRead bytes.
func (e *GDriveEnumerator) downloadFile(ctx context.Context, fileID string, maxRead int64) ([]byte, error) {
	if err := e.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	var content []byte
	err := e.withRetry(ctx, func() error {
		resp, err := e.svc.Files.Get(fileID).
			SupportsAllDrives(true).
			AcknowledgeAbuse(false).
			Context(ctx).
			Download()
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var reader io.Reader = resp.Body
		if maxRead > 0 {
			reader = io.LimitReader(resp.Body, maxRead+1)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("reading file body: %w", err)
		}
		if maxRead > 0 && int64(len(data)) > maxRead {
			content = nil // oversized
			return nil
		}
		content = data
		return nil
	})
	return content, err
}

// exportFile exports a Google Workspace document to the given MIME type.
func (e *GDriveEnumerator) exportFile(ctx context.Context, fileID, mimeType string, maxRead int64) ([]byte, error) {
	if err := e.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	var content []byte
	err := e.withRetry(ctx, func() error {
		resp, err := e.svc.Files.Export(fileID, mimeType).
			Context(ctx).
			Download()
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var reader io.Reader = resp.Body
		if maxRead > 0 {
			reader = io.LimitReader(resp.Body, maxRead+1)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("reading export body: %w", err)
		}
		if maxRead > 0 && int64(len(data)) > maxRead {
			content = nil // oversized
			return nil
		}
		content = data
		return nil
	})
	return content, err
}

// withRetry executes fn, retrying on transient Drive API errors with
// exponential backoff + jitter up to cfg.MaxRetries times.
func (e *GDriveEnumerator) withRetry(ctx context.Context, fn func() error) error {
	for attempt := 0; attempt <= e.cfg.MaxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		if !isRetryableGDriveError(err) {
			return err
		}

		if attempt == e.cfg.MaxRetries {
			return err
		}

		delay := gdriveRetryDelay(err, attempt, e.cfg.MaxBackoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil
}

// isRetryableGDriveError returns true for errors that warrant a retry.
func isRetryableGDriveError(err error) bool {
	var gErr *googleapi.Error
	ok := errors.As(err, &gErr)
	if !ok {
		return false
	}
	switch gErr.Code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	case http.StatusForbidden:
		if len(gErr.Errors) > 0 {
			switch gErr.Errors[0].Reason {
			case "rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded":
				return true
			}
		}
	}
	return false
}

// gdriveRetryDelay computes the sleep duration for attempt n, honoring Retry-After.
func gdriveRetryDelay(err error, attempt int, maxBackoff time.Duration) time.Duration {
	// Honor Retry-After header if present
	var gErr *googleapi.Error
	if errors.As(err, &gErr) {
		if ra := gErr.Header.Get("Retry-After"); ra != "" {
			if secs, parseErr := strconv.Atoi(ra); parseErr == nil && secs > 0 {
				d := time.Duration(secs) * time.Second
				if d < maxBackoff {
					return d
				}
				return maxBackoff
			}
		}
	}

	// Exponential backoff: 2^attempt * baseDelay + jitter
	// #nosec G115 -- attempt is bounded by gdriveMaxRetries; shift is safe.
	exp := time.Duration(1<<uint(attempt)) * gdriveBaseDelay
	// #nosec G404 -- jitter for retry backoff; cryptographic randomness unnecessary.
	jitter := time.Duration(rand.Int63n(1000)) * time.Millisecond
	d := exp + jitter
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

// extFromName returns the lowercased file extension (e.g., ".pdf") from a filename.
func extFromName(name string) string {
	return getExtension(name)
}

// ParseGDriveURL parses gdrive:// URLs. Supported forms:
//
//	gdrive://                  -> scope=GDriveScopeAll
//	gdrive://mine              -> scope=GDriveScopeMine
//	gdrive://shared-with-me    -> scope=GDriveScopeSharedWithMe
//	gdrive://shared-drives     -> scope=GDriveScopeSharedDrives
//	gdrive://drive/<id>        -> scope=GDriveScopeSingleDrive, driveID=<id>
func ParseGDriveURL(rawURL string) (scope GDriveScope, driveID string, ok bool) {
	if !strings.HasPrefix(rawURL, "gdrive://") {
		return 0, "", false
	}
	rest := strings.TrimPrefix(rawURL, "gdrive://")

	switch rest {
	case "":
		return GDriveScopeAll, "", true
	case "mine":
		return GDriveScopeMine, "", true
	case "shared-with-me":
		return GDriveScopeSharedWithMe, "", true
	case "shared-drives":
		return GDriveScopeSharedDrives, "", true
	}

	// Must be "drive/<id>" with no trailing path segments beyond id
	if !strings.HasPrefix(rest, "drive/") {
		return 0, "", false
	}
	id := strings.TrimPrefix(rest, "drive/")
	if id == "" {
		return 0, "", false
	}
	// Reject sub-paths like "drive/x/y/z"
	if strings.Contains(id, "/") {
		return 0, "", false
	}
	return GDriveScopeSingleDrive, id, true
}
