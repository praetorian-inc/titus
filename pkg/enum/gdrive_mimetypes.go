package enum

import "strings"

// gdriveAction is the per-file decision the enumerator makes from a MIME type.
type gdriveAction int

const (
	gdriveSkip     gdriveAction = iota // don't download (media, folder, shortcut, unsupported Workspace type)
	gdriveDownload                     // download raw bytes via files.get?alt=media
	gdriveExport                       // export a Google Workspace doc to a text-ish MIME type
)

// gdriveExportMIME maps a Google Workspace mimeType to the export mimeType
// we ask Drive for. Only types that yield readable text are listed; the rest
// fall through to gdriveSkip.
var gdriveExportMIME = map[string]string{
	"application/vnd.google-apps.document":     "text/plain",
	"application/vnd.google-apps.spreadsheet":  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"application/vnd.google-apps.presentation": "text/plain",
	"application/vnd.google-apps.script":       "application/vnd.google-apps.script+json",
}

// gdriveSkippedWorkspaceTypes is the set of Google Workspace mimeTypes we
// always skip because exporting them produces no useful text for secret
// scanning (drawings, maps, forms, sites, jamboards), or because they're
// structural and have no own content (folders, shortcuts, photos/video/audio).
var gdriveSkippedWorkspaceTypes = map[string]struct{}{
	"application/vnd.google-apps.folder":      {},
	"application/vnd.google-apps.shortcut":    {},
	"application/vnd.google-apps.photo":       {},
	"application/vnd.google-apps.video":       {},
	"application/vnd.google-apps.audio":       {},
	"application/vnd.google-apps.drawing":     {},
	"application/vnd.google-apps.map":         {},
	"application/vnd.google-apps.form":        {},
	"application/vnd.google-apps.site":        {},
	"application/vnd.google-apps.jam":         {},
	"application/vnd.google-apps.fusiontable": {},
}

// classifyGDriveMIME decides what to do with a Drive file based on its
// mimeType. Media files (image/audio/video/font), folders, shortcuts, and
// unsupported Workspace types are skipped. Workspace docs/sheets/slides/
// scripts are exported to text. Everything else is downloaded raw so the
// existing extractor pipeline (xlsx/docx/pdf/...) can run on it.
//
// The second return value is the export mimeType when action == gdriveExport.
func classifyGDriveMIME(mimeType string) (gdriveAction, string) {
	mt := strings.ToLower(strings.TrimSpace(mimeType))
	if mt == "" {
		// Unknown mimeType: be conservative and try to download. The
		// scanner's binary detector will discard if it's not text.
		return gdriveDownload, ""
	}

	if exportTo, ok := gdriveExportMIME[mt]; ok {
		return gdriveExport, exportTo
	}
	if _, skip := gdriveSkippedWorkspaceTypes[mt]; skip {
		return gdriveSkip, ""
	}

	switch {
	case strings.HasPrefix(mt, "image/"):
		return gdriveSkip, ""
	case strings.HasPrefix(mt, "audio/"):
		return gdriveSkip, ""
	case strings.HasPrefix(mt, "video/"):
		return gdriveSkip, ""
	case strings.HasPrefix(mt, "font/"):
		return gdriveSkip, ""
	}

	if strings.HasPrefix(mt, "application/vnd.google-apps.") {
		return gdriveSkip, ""
	}

	return gdriveDownload, ""
}
