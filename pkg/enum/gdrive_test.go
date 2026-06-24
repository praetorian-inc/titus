package enum

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestParseGDriveURL(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantScope   GDriveScope
		wantDriveID string
		wantOK      bool
	}{
		{"everything", "gdrive://", GDriveScopeAll, "", true},
		{"mine", "gdrive://mine", GDriveScopeMine, "", true},
		{"shared with me", "gdrive://shared-with-me", GDriveScopeSharedWithMe, "", true},
		{"shared drives", "gdrive://shared-drives", GDriveScopeSharedDrives, "", true},
		{"specific drive", "gdrive://drive/0AABBcc", GDriveScopeSingleDrive, "0AABBcc", true},
		{"empty drive id", "gdrive://drive/", 0, "", false},
		{"unknown selector", "gdrive://bogus", 0, "", false},
		{"wrong scheme colon", "gdrive:", 0, "", false},
		{"extra path segments", "gdrive://drive/x/y/z", 0, "", false},
		{"s3 url", "s3://foo", 0, "", false},
		{"local path", "/local", 0, "", false},
		{"empty string", "", 0, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, driveID, ok := ParseGDriveURL(tt.input)
			assert.Equal(t, tt.wantOK, ok, "ok mismatch")
			assert.Equal(t, tt.wantDriveID, driveID, "driveID mismatch")
			if tt.wantOK {
				assert.Equal(t, tt.wantScope, scope, "scope mismatch")
			}
		})
	}
}

func TestClassifyGDriveMIME(t *testing.T) {
	tests := []struct {
		name       string
		mimeType   string
		wantAction gdriveAction
		wantExport string
	}{
		{"empty string", "", gdriveDownload, ""},
		{"google document", "application/vnd.google-apps.document", gdriveExport, "text/plain"},
		{"google spreadsheet", "application/vnd.google-apps.spreadsheet", gdriveExport, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
		{"google presentation", "application/vnd.google-apps.presentation", gdriveExport, "text/plain"},
		{"google script", "application/vnd.google-apps.script", gdriveExport, "application/vnd.google-apps.script+json"},
		{"folder", "application/vnd.google-apps.folder", gdriveSkip, ""},
		{"shortcut", "application/vnd.google-apps.shortcut", gdriveSkip, ""},
		{"google photo", "application/vnd.google-apps.photo", gdriveSkip, ""},
		{"google drawing", "application/vnd.google-apps.drawing", gdriveSkip, ""},
		{"image/jpeg", "image/jpeg", gdriveSkip, ""},
		{"audio/mpeg", "audio/mpeg", gdriveSkip, ""},
		{"video/mp4", "video/mp4", gdriveSkip, ""},
		{"font/ttf", "font/ttf", gdriveSkip, ""},
		{"application/pdf", "application/pdf", gdriveDownload, ""},
		{"text/plain", "text/plain", gdriveDownload, ""},
		{"unknown workspace type", "application/vnd.google-apps.unknown", gdriveSkip, ""},
		{"application/octet-stream", "application/octet-stream", gdriveDownload, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, export := classifyGDriveMIME(tt.mimeType)
			assert.Equal(t, tt.wantAction, action, "action mismatch")
			assert.Equal(t, tt.wantExport, export, "export MIME mismatch")
		})
	}
}

func newTestGDriveEnumeratorDirect(t *testing.T, srv *httptest.Server) *GDriveEnumerator {
	t.Helper()
	svc, err := drive.NewService(
		t.Context(),
		option.WithEndpoint(srv.URL+"/drive/v3/"),
		option.WithoutAuthentication(),
	)
	require.NoError(t, err)

	return &GDriveEnumerator{
		svc: svc,
		cfg: GDriveConfig{
			Token:      "test-token",
			RateLimit:  1000,
			MaxRetries: 3,
			MaxBackoff: 2 * time.Second,
		},
		limiter: rate.NewLimiter(rate.Limit(1000), 1000),
	}
}

type fileStub struct {
	id       string
	name     string
	mimeType string
}

func driveFileListJSON(files []fileStub) string {
	type ownerStub struct {
		EmailAddress string `json:"emailAddress"`
	}
	type fileJSON struct {
		Id          string      `json:"id"`
		Name        string      `json:"name"`
		MimeType    string      `json:"mimeType"`
		Size        string      `json:"size"`
		Owners      []ownerStub `json:"owners"`
		WebViewLink string      `json:"webViewLink"`
		DriveId     string      `json:"driveId"`
	}
	type listResp struct {
		Files         []fileJSON `json:"files"`
		NextPageToken string     `json:"nextPageToken"`
	}
	resp := listResp{}
	for _, f := range files {
		resp.Files = append(resp.Files, fileJSON{
			Id:       f.id,
			Name:     f.name,
			MimeType: f.mimeType,
			Size:     "100",
		})
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

type driveStub struct {
	id   string
	name string
}

func drivesListJSON(drives []driveStub) string {
	type driveJSON struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	}
	type listResp struct {
		Drives        []driveJSON `json:"drives"`
		NextPageToken string      `json:"nextPageToken"`
	}
	resp := listResp{}
	for _, d := range drives {
		resp.Drives = append(resp.Drives, driveJSON{Id: d.id, Name: d.name})
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

func TestGDriveEnumerator_Enumerate_HappyPath(t *testing.T) {
	const textContent = "secret_key=AKIAIOSFODNN7EXAMPLE"

	callCounts := map[string]int{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		q := r.URL.Query().Get("q")

		w.Header().Set("Content-Type", "application/json")

		switch {
		case path == "/drive/v3/drives":
			callCounts["drives"]++
			_, _ = fmt.Fprint(w, drivesListJSON(nil))

		case path == "/drive/v3/files" && strings.Contains(q, "'me' in owners"):
			callCounts["myDrive"]++
			_, _ = fmt.Fprint(w, driveFileListJSON([]fileStub{
				{id: "file1", name: "credentials.txt", mimeType: "text/plain"},
				{id: "file2", name: "photo.jpg", mimeType: "image/jpeg"},
			}))

		case path == "/drive/v3/files" && strings.Contains(q, "sharedWithMe"):
			callCounts["sharedWithMe"]++
			_, _ = fmt.Fprint(w, driveFileListJSON(nil))

		case path == "/drive/v3/files/file1":
			callCounts["download"]++
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, textContent)

		default:
			t.Logf("unhandled: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := newTestGDriveEnumeratorDirect(t, srv)

	var blobs []struct {
		content []byte
		prov    types.Provenance
	}

	err := e.Enumerate(t.Context(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, struct {
			content []byte
			prov    types.Provenance
		}{content, prov})
		return nil
	})
	require.NoError(t, err)

	require.Len(t, blobs, 1, "expected exactly one blob")
	assert.Equal(t, textContent, string(blobs[0].content))

	ep, ok := blobs[0].prov.(types.ExtendedProvenance)
	require.True(t, ok, "expected ExtendedProvenance")
	assert.Equal(t, "gdrive", ep.Payload["source"])
	assert.Equal(t, "file1", ep.Payload["file_id"])

	assert.Equal(t, 1, callCounts["download"], "expected exactly one download (file1 only)")
	assert.Equal(t, 1, callCounts["myDrive"])
	assert.Equal(t, 1, callCounts["sharedWithMe"])
	assert.Equal(t, 1, callCounts["drives"])
}

func TestGDriveEnumerator_RateLimit_RespectsRetryAfter(t *testing.T) {
	const textContent = "hello world"
	downloadAttempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		q := r.URL.Query().Get("q")

		switch {
		case path == "/drive/v3/files" && strings.Contains(q, "'me' in owners"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, driveFileListJSON([]fileStub{
				{id: "f1", name: "secret.txt", mimeType: "text/plain"},
			}))

		case path == "/drive/v3/files" && strings.Contains(q, "sharedWithMe"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, driveFileListJSON(nil))

		case path == "/drive/v3/drives":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, drivesListJSON(nil))

		case path == "/drive/v3/files/f1":
			downloadAttempts++
			if downloadAttempts == 1 {
				w.Header().Set("Retry-After", "1")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = fmt.Fprint(w, `{"error":{"code":429,"message":"rate limit","errors":[{"reason":"rateLimitExceeded"}]}}`)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, textContent)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := newTestGDriveEnumeratorDirect(t, srv)

	start := time.Now()
	var blobCount int
	err := e.Enumerate(t.Context(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobCount++
		return nil
	})
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, 1, blobCount, "expected one blob after retry")
	assert.GreaterOrEqual(t, elapsed, time.Second, "expected at least 1s delay from Retry-After")
}

func TestGDriveEnumerator_NonRetryable403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		q := r.URL.Query().Get("q")

		switch {
		case path == "/drive/v3/files" && strings.Contains(q, "'me' in owners"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, driveFileListJSON([]fileStub{
				{id: "f1", name: "blocked.txt", mimeType: "text/plain"},
				{id: "f2", name: "ok.txt", mimeType: "text/plain"},
			}))

		case path == "/drive/v3/files" && strings.Contains(q, "sharedWithMe"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, driveFileListJSON(nil))

		case path == "/drive/v3/drives":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, drivesListJSON(nil))

		case path == "/drive/v3/files/f1":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":{"code":403,"message":"forbidden","errors":[{"reason":"forbidden"}]}}`)

		case path == "/drive/v3/files/f2":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "ok content")

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := newTestGDriveEnumeratorDirect(t, srv)

	var blobCount int
	err := e.Enumerate(t.Context(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobCount++
		return nil
	})

	require.NoError(t, err, "enumeration must complete despite per-file error")
	assert.Equal(t, 1, blobCount, "f2 should still be processed")
}

func TestNewGDriveEnumerator_AuthValidation(t *testing.T) {
	tests := []struct {
		name        string
		cfg         GDriveConfig
		wantErr     bool
		errContains string
	}{
		{
			name:    "token only",
			cfg:     GDriveConfig{Token: "ya29.access"},
			wantErr: false,
		},
		{
			name: "refresh token with client credentials",
			cfg: GDriveConfig{
				RefreshToken: "1//04refresh",
				ClientID:     "client.id",
				ClientSecret: "client-secret",
			},
			wantErr: false,
		},
		{
			name: "refresh token without ClientID",
			cfg: GDriveConfig{
				RefreshToken: "1//04refresh",
				ClientSecret: "client-secret",
			},
			wantErr:     true,
			errContains: "ClientID",
		},
		{
			name: "refresh token without ClientSecret",
			cfg: GDriveConfig{
				RefreshToken: "1//04refresh",
				ClientID:     "client.id",
			},
			wantErr:     true,
			errContains: "ClientSecret",
		},
		{
			name:        "nothing provided",
			cfg:         GDriveConfig{},
			wantErr:     true,
			errContains: "must provide either Token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewGDriveEnumerator(tt.cfg)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, e)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, e)
			}
		})
	}
}

func TestGDriveEnumerator_DeduplicatesByFileID(t *testing.T) {
	var downloadHits int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		q := r.URL.Query().Get("q")
		driveId := r.URL.Query().Get("driveId")
		w.Header().Set("Content-Type", "application/json")

		switch {
		case path == "/drive/v3/files" && strings.Contains(q, "'me' in owners"):
			_, _ = fmt.Fprint(w, driveFileListJSON(nil))

		case path == "/drive/v3/files" && strings.Contains(q, "sharedWithMe"):
			_, _ = fmt.Fprint(w, driveFileListJSON([]fileStub{
				{id: "dup1", name: "shared.txt", mimeType: "text/plain"},
			}))

		case path == "/drive/v3/drives":
			_, _ = fmt.Fprint(w, drivesListJSON([]driveStub{{id: "dr1", name: "drive-one"}}))

		case path == "/drive/v3/files" && driveId == "dr1":
			// Same file ID re-appears inside the shared drive listing.
			_, _ = fmt.Fprint(w, driveFileListJSON([]fileStub{
				{id: "dup1", name: "shared.txt", mimeType: "text/plain"},
			}))

		case path == "/drive/v3/files/dup1":
			downloadHits++
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "content_here")

		default:
			t.Logf("unhandled: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := newTestGDriveEnumeratorDirect(t, srv)

	var blobCount int
	err := e.Enumerate(t.Context(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobCount++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, blobCount, "callback should fire exactly once for duplicate file id")
	assert.Equal(t, 1, downloadHits, "download endpoint should be hit exactly once")
}

func TestGDriveEnumerator_Scopes(t *testing.T) {
	type want struct {
		myDrive       bool
		sharedWithMe  bool
		drivesList    bool
		driveIdInList string // expected driveId query param in files.list, or "" if none
	}
	cases := []struct {
		name    string
		scope   GDriveScope
		driveID string
		wants   want
	}{
		{"mine", GDriveScopeMine, "", want{myDrive: true}},
		{"shared-with-me", GDriveScopeSharedWithMe, "", want{sharedWithMe: true}},
		{"shared-drives", GDriveScopeSharedDrives, "", want{drivesList: true, driveIdInList: "dr1"}},
		{"single drive", GDriveScopeSingleDrive, "dr1", want{driveIdInList: "dr1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := map[string]int{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := r.URL.Path
				q := r.URL.Query().Get("q")
				driveId := r.URL.Query().Get("driveId")
				w.Header().Set("Content-Type", "application/json")

				switch {
				case path == "/drive/v3/files" && strings.Contains(q, "'me' in owners"):
					hits["myDrive"]++
					_, _ = fmt.Fprint(w, driveFileListJSON(nil))
				case path == "/drive/v3/files" && strings.Contains(q, "sharedWithMe"):
					hits["sharedWithMe"]++
					_, _ = fmt.Fprint(w, driveFileListJSON(nil))
				case path == "/drive/v3/drives":
					hits["drives"]++
					_, _ = fmt.Fprint(w, drivesListJSON([]driveStub{{id: "dr1", name: "drive-one"}}))
				case path == "/drive/v3/files" && driveId != "":
					hits["driveFiles:"+driveId]++
					_, _ = fmt.Fprint(w, driveFileListJSON(nil))
				default:
					t.Logf("unhandled: %s %s", r.Method, r.URL)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			e := newTestGDriveEnumeratorDirect(t, srv)
			e.cfg.Scope = tc.scope
			e.cfg.DriveID = tc.driveID

			err := e.Enumerate(t.Context(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
				return nil
			})
			require.NoError(t, err)

			if tc.wants.myDrive {
				assert.Equal(t, 1, hits["myDrive"], "expected myDrive listing")
			} else {
				assert.Equal(t, 0, hits["myDrive"], "myDrive listing should not happen")
			}
			if tc.wants.sharedWithMe {
				assert.Equal(t, 1, hits["sharedWithMe"], "expected sharedWithMe listing")
			} else {
				assert.Equal(t, 0, hits["sharedWithMe"], "sharedWithMe listing should not happen")
			}
			if tc.wants.drivesList {
				assert.GreaterOrEqual(t, hits["drives"], 1, "expected drives.list call")
			} else {
				assert.Equal(t, 0, hits["drives"], "drives.list should not happen")
			}
			if tc.wants.driveIdInList != "" {
				key := "driveFiles:" + tc.wants.driveIdInList
				assert.GreaterOrEqual(t, hits[key], 1, "expected files.list with driveId=%s", tc.wants.driveIdInList)
			}
		})
	}
}

func TestNewGDriveEnumerator_RateLimitDefault(t *testing.T) {
	e, err := NewGDriveEnumerator(GDriveConfig{Token: "x"})
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, rate.Limit(16), e.limiter.Limit(), "default rate limit should be 16 RPS")
}

func TestGDriveEnumerator_RefreshToken_Refresh(t *testing.T) {
	var tokenHits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"access_token":"new-token-123","expires_in":3600,"token_type":"Bearer"}`)

		case "/drive/v3/drives":
			assert.Equal(t, "Bearer new-token-123", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, drivesListJSON(nil))

		case "/drive/v3/files":
			assert.Equal(t, "Bearer new-token-123", r.Header.Get("Authorization"))
			q := r.URL.Query().Get("q")
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(q, "'me' in owners") {
				_, _ = fmt.Fprint(w, driveFileListJSON([]fileStub{{id: "rf1", name: "secret.txt", mimeType: "text/plain"}}))
			} else if strings.Contains(q, "sharedWithMe") {
				_, _ = fmt.Fprint(w, driveFileListJSON(nil))
			} else {
				t.Logf("unhandled files query: %s", q)
				http.NotFound(w, r)
			}

		case "/drive/v3/files/rf1":
			assert.Equal(t, "Bearer new-token-123", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "refresh_token_content=works")

		default:
			t.Logf("unhandled: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx := context.Background()

	conf := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: srv.URL + "/token",
		},
	}

	expiredToken := &oauth2.Token{
		AccessToken:  "",
		RefreshToken: "test-refresh-token",
		Expiry:       time.Now().Add(-time.Second),
	}

	svc, err := drive.NewService(ctx,
		option.WithEndpoint(srv.URL+"/drive/v3/"),
		option.WithTokenSource(conf.TokenSource(ctx, expiredToken)),
	)
	require.NoError(t, err)

	e := &GDriveEnumerator{
		svc: svc,
		cfg: GDriveConfig{
			RefreshToken: "test-refresh-token",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RateLimit:    1000,
			MaxRetries:   3,
			MaxBackoff:   2 * time.Second,
		},
		limiter: rate.NewLimiter(rate.Limit(1000), 1000),
	}

	var blobs [][]byte
	err = e.Enumerate(t.Context(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		blobs = append(blobs, content)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, int32(1), tokenHits.Load(), "token endpoint should be hit exactly once")
	require.Len(t, blobs, 1)
	assert.Equal(t, "refresh_token_content=works", string(blobs[0]))
}

// makeMinimalXLSX builds the smallest valid xlsx bytes containing one
// xl/sharedStrings.xml with a known string, suitable for extractXLSX.
func makeMinimalXLSX(sharedString string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	addFile := func(name, content string) {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(content))
	}
	addFile("xl/sharedStrings.xml", `<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1"><si><t>`+sharedString+`</t></si></sst>`)
	_ = zw.Close()
	return buf.Bytes()
}

// TestGDriveEnumerator_SheetsXLSXExtraction verifies that a Google Sheet
// (no file extension in Drive name) is correctly routed through extractXLSX
// when ExtractArchives includes "xlsx".
func TestGDriveEnumerator_SheetsXLSXExtraction(t *testing.T) {
	const secretValue = "api_key=supersecret123"
	xlsxBytes := makeMinimalXLSX(secretValue)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case path == "/drive/v3/drives":
			_, _ = fmt.Fprint(w, drivesListJSON(nil))
		case path == "/drive/v3/files" && strings.Contains(q, "'me' in owners"):
			_, _ = fmt.Fprint(w, driveFileListJSON([]fileStub{
				{id: "sheet1", name: "Q4 Budget", mimeType: "application/vnd.google-apps.spreadsheet"},
			}))
		case path == "/drive/v3/files" && strings.Contains(q, "sharedWithMe"):
			_, _ = fmt.Fprint(w, driveFileListJSON(nil))
		case path == "/drive/v3/files/sheet1/export":
			w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
			_, _ = w.Write(xlsxBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := newTestGDriveEnumeratorDirect(t, srv)
	e.cfg.Config = Config{ExtractArchives: "xlsx", ExtractLimits: DefaultExtractionLimits()}

	var extracted []string
	err := e.Enumerate(t.Context(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		extracted = append(extracted, string(content))
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, extracted, "expected at least one extracted blob from Q4 Budget sheet")
	found := false
	for _, s := range extracted {
		if strings.Contains(s, secretValue) {
			found = true
			break
		}
	}
	assert.True(t, found, "extracted content should contain the known string %q", secretValue)
}
