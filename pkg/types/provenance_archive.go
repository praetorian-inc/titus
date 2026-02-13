package types

import "fmt"

// ArchiveProvenance tracks content extracted from binary archives.
type ArchiveProvenance struct {
	ArchivePath string // path to the archive/binary file
	MemberPath  string // path within the archive (e.g., "xl/sharedStrings.xml")
}

// Kind returns "archive".
func (a ArchiveProvenance) Kind() string {
	return "archive"
}

// Path returns the archive path with member path.
func (a ArchiveProvenance) Path() string {
	return fmt.Sprintf("%s:%s", a.ArchivePath, a.MemberPath)
}
