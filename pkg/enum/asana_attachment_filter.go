package enum

import (
	"path/filepath"
	"strings"
)

// asanaSkipAttachmentExt returns true if the file extension is in a hard-coded
// skip list of media/binary types that essentially never contain secrets.
// Used to avoid downloading large media attachments from Asana, since the
// Asana API does not expose a mime_type field on the attachment resource.
func asanaSkipAttachmentExt(name string) bool {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	if ext == "" {
		return false
	}
	_, skip := asanaSkipExtensions[ext]
	return skip
}

var asanaSkipExtensions = map[string]struct{}{
	// images
	"png": {}, "jpg": {}, "jpeg": {}, "gif": {}, "bmp": {}, "webp": {},
	"ico": {}, "tif": {}, "tiff": {}, "heic": {}, "heif": {},
	"psd": {}, "ai": {}, "sketch": {}, "fig": {}, "xd": {},
	// audio
	"mp3": {}, "wav": {}, "flac": {}, "ogg": {}, "m4a": {}, "aac": {},
	"wma": {}, "opus": {},
	// video
	"mp4": {}, "mov": {}, "avi": {}, "mkv": {}, "webm": {}, "m4v": {},
	"wmv": {}, "flv": {}, "mpeg": {}, "mpg": {}, "3gp": {},
	// fonts
	"ttf": {}, "otf": {}, "woff": {}, "woff2": {}, "eot": {},
	// disk images / installers (binary, very rarely text-bearing)
	"dmg": {}, "iso": {}, "img": {},
}
