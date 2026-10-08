package enum

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"unicode/utf16"

	"github.com/masahiro331/go-ext4-filesystem/ext4"
	"github.com/masahiro331/go-xfs-filesystem/xfs"
	"github.com/praetorian-inc/titus/pkg/types"
)

const (
	gptSignature = "EFI PART"
	mbrSignature = 0xAA55
	extMagic     = 0xEF53
	extMagicOff  = 0x438
	lvmMagicOff  = 512
	lvmMagic     = "LABELONE"
	xfsMagic     = "XFSB"
)

var errUnsupportedFS = errors.New("unsupported filesystem")

type amiVolume struct {
	Label      string
	Disk       io.ReaderAt
	Size       int64
	SnapshotID string
	Device     string
	close      func()
}

type diskPartition struct {
	Name   string
	Offset int64
	Size   int64
}

func closeVolumes(volumes []amiVolume) {
	for _, vol := range volumes {
		if vol.close != nil {
			vol.close()
		}
	}
}

func scanAMIDisk(ctx context.Context, vol amiVolume, config Config, ig gitIgnore, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) (int, []string, error) {
	if vol.Size <= 0 {
		return 0, nil, fmt.Errorf("disk has no size")
	}
	parts, kind, err := readPartitions(vol.Disk, vol.Size)
	if err != nil {
		return 0, nil, err
	}
	if len(parts) == 0 {
		parts = []diskPartition{{Name: "disk", Offset: 0, Size: vol.Size}}
		kind = "raw"
	}

	var opened int
	var notes []string
	for _, part := range parts {
		if err := ctx.Err(); err != nil {
			return opened, notes, err
		}
		fsys, fsKind, err := openPartitionFS(vol.Disk, part)
		if errors.Is(err, errUnsupportedFS) {
			notes = append(notes, fmt.Sprintf("skip %s partition %s at %d: %s", kind, part.Name, part.Offset, filesystemHint(vol.Disk, part.Offset)))
			continue
		}
		if err != nil {
			return opened, notes, fmt.Errorf("opening %s filesystem at %d: %w", fsKind, part.Offset, err)
		}
		opened++
		if err := walkAMIFilesystem(ctx, fsys, vol, config, ig, callback); err != nil {
			return opened, notes, err
		}
	}
	return opened, notes, nil
}

func readPartitions(r io.ReaderAt, diskSize int64) ([]diskPartition, string, error) {
	for _, sector := range []int{512, 4096} {
		if diskSize < int64(sector*2) {
			continue
		}
		parts, found, err := readGPT(r, diskSize, sector)
		if err != nil {
			return nil, "gpt", err
		}
		if found {
			return parts, "gpt", nil
		}
	}
	for _, sector := range []int{512, 4096} {
		if diskSize < int64(sector) {
			continue
		}
		parts, found := readMBR(r, diskSize, sector)
		if found {
			return parts, "mbr", nil
		}
	}
	return nil, "", nil
}

func readGPT(r io.ReaderAt, diskSize int64, sector int) ([]diskPartition, bool, error) {
	header := make([]byte, sector)
	if _, err := r.ReadAt(header, int64(sector)); err != nil {
		return nil, false, nil
	}
	if string(header[:8]) != gptSignature {
		return nil, false, nil
	}
	if len(header) < 92 {
		return nil, true, fmt.Errorf("GPT header is shorter than 92 bytes")
	}
	headerSize := binary.LittleEndian.Uint32(header[12:16])
	if headerSize < 92 || int(headerSize) > len(header) {
		return nil, true, fmt.Errorf("GPT header size %d is invalid", headerSize)
	}
	stored := binary.LittleEndian.Uint32(header[16:20])
	if gptHeaderCRC(header[:headerSize]) != stored {
		return nil, true, fmt.Errorf("GPT header checksum mismatch")
	}
	entryLBA := binary.LittleEndian.Uint64(header[72:80])
	entryCount := binary.LittleEndian.Uint32(header[80:84])
	entrySize := binary.LittleEndian.Uint32(header[84:88])
	if entryCount == 0 || entrySize < 128 || entryLBA == 0 {
		return nil, true, fmt.Errorf("GPT partition entry table is invalid")
	}
	tableBytes := int64(entryCount) * int64(entrySize)
	if tableBytes > 16*1024*1024 {
		return nil, true, fmt.Errorf("GPT partition entry table is too large")
	}
	table := make([]byte, tableBytes)
	if _, err := r.ReadAt(table, int64(entryLBA)*int64(sector)); err != nil {
		return nil, true, fmt.Errorf("reading GPT partition entries: %w", err)
	}
	var parts []diskPartition
	for i := uint32(0); i < entryCount; i++ {
		ent := table[int(i)*int(entrySize) : int(i+1)*int(entrySize)]
		if gptGUIDEmpty(ent[:16]) {
			continue
		}
		first := binary.LittleEndian.Uint64(ent[32:40])
		last := binary.LittleEndian.Uint64(ent[40:48])
		if last < first {
			continue
		}
		offset := int64(first) * int64(sector)
		size := int64(last-first+1) * int64(sector)
		if offset < 0 || offset >= diskSize || size <= 0 {
			continue
		}
		if offset+size > diskSize {
			size = diskSize - offset
		}
		name := gptName(ent[56:128])
		if name == "" {
			name = fmt.Sprintf("p%d", i+1)
		}
		parts = append(parts, diskPartition{Name: name, Offset: offset, Size: size})
	}
	return parts, true, nil
}

func gptHeaderCRC(header []byte) uint32 {
	buf := append([]byte(nil), header...)
	binary.LittleEndian.PutUint32(buf[16:20], 0)
	return crc32.ChecksumIEEE(buf)
}

func gptGUIDEmpty(guid []byte) bool {
	for _, b := range guid {
		if b != 0 {
			return false
		}
	}
	return true
}

func gptName(raw []byte) string {
	if len(raw) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		c := binary.LittleEndian.Uint16(raw[i : i+2])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return strings.TrimSpace(string(utf16.Decode(u)))
}

func readMBR(r io.ReaderAt, diskSize int64, sector int) ([]diskPartition, bool) {
	buf := make([]byte, sector)
	if _, err := r.ReadAt(buf, 0); err != nil || len(buf) < 512 {
		return nil, false
	}
	if binary.LittleEndian.Uint16(buf[510:512]) != mbrSignature {
		return nil, false
	}
	var parts []diskPartition
	for i := range 4 {
		ent := buf[446+i*16 : 446+(i+1)*16]
		typ := ent[4]
		// Empty, protective GPT, or extended partitions. Extended partitions are
		// uncommon on cloud AMIs and are not walked.
		if typ == 0 || typ == 0xEE || typ == 0x05 || typ == 0x0F {
			continue
		}
		start := binary.LittleEndian.Uint32(ent[8:12])
		count := binary.LittleEndian.Uint32(ent[12:16])
		if start == 0 || count == 0 {
			continue
		}
		offset := int64(start) * int64(sector)
		size := int64(count) * int64(sector)
		if offset < 0 || offset >= diskSize || size <= 0 {
			continue
		}
		if offset+size > diskSize {
			size = diskSize - offset
		}
		parts = append(parts, diskPartition{Name: fmt.Sprintf("p%d", i+1), Offset: offset, Size: size})
	}
	return parts, len(parts) > 0
}

func openPartitionFS(r io.ReaderAt, part diskPartition) (fs.FS, string, error) {
	kind := probeFilesystem(r, part.Offset, part.Size)
	if kind == "" {
		return nil, "", errUnsupportedFS
	}
	section := io.NewSectionReader(r, part.Offset, part.Size)
	switch kind {
	case "ext4":
		fsys, err := ext4.NewFS(*section, nil)
		if err != nil {
			return nil, kind, err
		}
		return fsys, kind, nil
	case "xfs":
		fsys, err := xfs.NewFS(*section, nil)
		if err != nil {
			return nil, kind, err
		}
		return fsys, kind, nil
	default:
		return nil, kind, errUnsupportedFS
	}
}

func probeFilesystem(r io.ReaderAt, offset, size int64) string {
	if size < extMagicOff+2 {
		return ""
	}
	var magic [4]byte
	if _, err := r.ReadAt(magic[:], offset); err == nil && string(magic[:]) == xfsMagic {
		return "xfs"
	}
	var ext [2]byte
	if _, err := r.ReadAt(ext[:], offset+extMagicOff); err == nil && binary.LittleEndian.Uint16(ext[:]) == extMagic {
		return "ext4"
	}
	return ""
}

func filesystemHint(r io.ReaderAt, offset int64) string {
	var magic [8]byte
	if _, err := r.ReadAt(magic[:], offset+lvmMagicOff); err == nil && string(magic[:]) == lvmMagic {
		return "LVM volumes are not supported"
	}
	return "unsupported filesystem (want ext2/3/4 or xfs)"
}

func walkAMIFilesystem(ctx context.Context, fsys fs.FS, vol amiVolume, config Config, ig gitIgnore, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// These filesystem libraries special-case "/" and reject ".".
	return fs.WalkDir(fsys, "/", func(p string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			fmtSkip(vol.Label, p, err)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		typ := d.Type()
		if typ&(fs.ModeSymlink|fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeIrregular) != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			fmtSkip(vol.Label, p, err)
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
			return nil
		}
		rel := cleanAMIPath(p)
		if rel == "" || rel == "." {
			return nil
		}
		if ig != nil && ig.MatchesPath(rel) {
			return nil
		}
		if amiSkipUnread(rel, config) {
			return nil
		}
		maxRead := config.MaxFileSize
		if maxRead <= 0 {
			maxRead = 100 * 1024 * 1024
		}
		if info.Size() > maxRead {
			return nil
		}
		content, err := readAMIFile(fsys, p, maxRead)
		if err != nil {
			fmtSkip(vol.Label, rel, err)
			return nil
		}
		if int64(len(content)) > maxRead || len(content) == 0 {
			return nil
		}
		return emitAMIFile(content, vol, rel, config, callback)
	})
}

func readAMIFile(fsys fs.FS, name string, maxRead int64) ([]byte, error) {
	f, err := fsys.Open(strings.TrimPrefix(name, "/"))
	if err != nil {
		f, err = fsys.Open(name)
		if err != nil {
			return nil, err
		}
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxRead+1))
}

func emitAMIFile(content []byte, vol amiVolume, rel string, config Config, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	display := vol.Label + "/" + rel
	content, isText := textContent(content)
	if !isText {
		if config.ExtractArchives == "" || !shouldExtract(config, getExtension(rel)) {
			return nil
		}
		extracted, err := ExtractText(rel, content, config.ExtractLimits)
		if err != nil || len(extracted) == 0 {
			return nil
		}
		for _, ec := range extracted {
			blobID := types.ComputeBlobID(ec.Content)
			prov := types.ArchiveProvenance{ArchivePath: display, MemberPath: ec.Name}
			if err := callback(ec.Content, blobID, prov); err != nil {
				return err
			}
		}
		return nil
	}
	blobID := types.ComputeBlobID(content)
	prov := types.ExtendedProvenance{Payload: map[string]interface{}{
		"source":   "ami",
		"path":     display,
		"snapshot": vol.SnapshotID,
		"device":   vol.Device,
	}}
	return callback(content, blobID, prov)
}

func cleanAMIPath(p string) string {
	p = strings.TrimPrefix(p, "/")
	p = path.Clean(p)
	if p == "." {
		return ""
	}
	return strings.TrimPrefix(p, "./")
}

func fmtSkip(label, name string, err error) {
	fmt.Fprintf(os.Stderr, "[ami] skip %s/%s: %v\n", label, strings.TrimPrefix(name, "/"), err)
}

// amiBinaryExts are file types that almost never hold recoverable secrets and
// are expensive to pull block-by-block from EBS. Extraction can still opt in.
var amiBinaryExts = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {}, ".ico": {},
	".bmp": {}, ".tif": {}, ".tiff": {}, ".heic": {}, ".heif": {}, ".psd": {},
	".mp3": {}, ".wav": {}, ".flac": {}, ".ogg": {}, ".m4a": {}, ".aac": {},
	".mp4": {}, ".mov": {}, ".avi": {}, ".mkv": {}, ".webm": {}, ".m4v": {},
	".ttf": {}, ".otf": {}, ".woff": {}, ".woff2": {}, ".eot": {},
	".so": {}, ".o": {}, ".a": {}, ".ko": {}, ".pyc": {}, ".pyo": {},
	".class": {}, ".dll": {}, ".exe": {}, ".dylib": {}, ".bin": {},
}

func amiSkipUnread(rel string, config Config) bool {
	ext := getExtension(rel)
	if _, ok := amiBinaryExts[ext]; !ok {
		return false
	}
	return !shouldExtract(config, ext)
}
