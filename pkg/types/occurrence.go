package types

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/praetorian-inc/titus/pkg/repoid"
)

// Occurrence is one place where a blob's content was found: a repository
// location (path at its earliest commit, or the working tree), a plain file,
// or a location recorded by an extended or archive source.
type Occurrence struct {
	Kind         string    // "git" | "file" | "extended" | "archive"
	Repository   string    // git only; "" otherwise
	Path         string    // repo-relative (git) or as typed / source-native (others)
	AbsolutePath string    // working tree, plain folder, and committed locations of remote-less repos
	Commit       string    // full hash; "" = none
	CommitDate   time.Time // zero = none
	WorkingTree  bool
	HostRecorded bool // false only for legacy git rows
}

const (
	shortCommitLen     = 7
	commitDateLayout   = "2006-01-02"
	fieldSeparator     = "  "
	labelWorkingTree   = "working tree"
	labelHostNotRecord = "host not recorded"
)

// OccurrencesOf returns every occurrence a provenance describes: one per
// GitProvenance.Locations entry (or the primary location when Locations is
// empty), and one for every other provenance kind.
func OccurrencesOf(p Provenance) []Occurrence {
	switch v := p.(type) {
	case GitProvenance:
		return gitOccurrences(v)
	case FileProvenance:
		abs, err := filepath.Abs(v.FilePath)
		if err != nil {
			abs = ""
		}
		return []Occurrence{{Kind: v.Kind(), Path: v.FilePath, AbsolutePath: abs, HostRecorded: true}}
	default:
		return []Occurrence{{Kind: p.Kind(), Path: p.Path(), HostRecorded: true}}
	}
}

func gitOccurrences(g GitProvenance) []Occurrence {
	locs := g.Locations
	if len(locs) == 0 {
		locs = []GitLocation{{Path: g.BlobPath, Commit: g.Commit}}
	}
	out := make([]Occurrence, 0, len(locs))
	for _, l := range locs {
		o := Occurrence{
			Kind:         g.Kind(),
			Repository:   g.RepoPath,
			Path:         l.Path,
			WorkingTree:  l.WorkingTree,
			HostRecorded: true,
		}
		if l.Commit != nil {
			o.Commit = l.Commit.CommitID
			o.CommitDate = l.Commit.CommitterTimestamp
		}
		// Committed content of a host-identified repository merges across
		// folders; everything else stays separated by its absolute folder.
		if g.RepoRoot != "" && (l.WorkingTree || !g.RemoteIdentity) {
			o.AbsolutePath = filepath.Join(g.RepoRoot, l.Path)
		}
		out = append(out, o)
	}
	return out
}

// MergeOccurrences reconciles location rows with provenance rows for one blob.
// Every row is kept. A provenance row is added only when no row covers it; an
// uncovered git provenance is a legacy row and is marked HostRecorded=false,
// with any userinfo redacted from its stored repository. A commitless,
// non-working-tree git occurrence is dropped when another occurrence of the
// same (repository, path) has a commit. The result is deduplicated and sorted.
func MergeOccurrences(rows []Occurrence, provs []Provenance) []Occurrence {
	covered := make(map[coverKey]bool, len(rows))
	for _, r := range rows {
		covered[coverKeyOf(r)] = true
	}
	all := slices.Clone(rows)
	for _, p := range provs {
		for _, o := range legacyOccurrencesOf(p) {
			if covered[coverKeyOf(o)] {
				continue
			}
			if o.Kind == "git" {
				o.HostRecorded = false
				o.Repository = repoid.RedactUserinfo(o.Repository)
			}
			all = append(all, o)
		}
	}
	return sortedUnique(dropCommitlessDuplicates(all))
}

// legacyOccurrencesOf maps a stored provenance row. Unlike OccurrencesOf it
// never derives an absolute path: a stored file path is relative to the cwd of
// the scan that wrote it, not of the reader.
func legacyOccurrencesOf(p Provenance) []Occurrence {
	if f, ok := p.(FileProvenance); ok {
		return []Occurrence{{Kind: f.Kind(), Path: f.FilePath, HostRecorded: true}}
	}
	return OccurrencesOf(p)
}

type coverKey struct{ kind, repository, path, commit string }

func coverKeyOf(o Occurrence) coverKey {
	if o.Kind == "git" {
		return coverKey{o.Kind, o.Repository, o.Path, o.Commit}
	}
	return coverKey{kind: o.Kind, path: o.Path}
}

type repoPath struct{ repository, path string }

func dropCommitlessDuplicates(occs []Occurrence) []Occurrence {
	committed := make(map[repoPath]bool)
	for _, o := range occs {
		if o.Kind == "git" && o.Commit != "" {
			committed[repoPath{o.Repository, o.Path}] = true
		}
	}
	return slices.DeleteFunc(occs, func(o Occurrence) bool {
		return o.Kind == "git" && o.Commit == "" && !o.WorkingTree && committed[repoPath{o.Repository, o.Path}]
	})
}

type identityKey struct {
	kind, repository, path, absolutePath, commit string
	workingTree, hostRecorded                    bool
}

func sortedUnique(occs []Occurrence) []Occurrence {
	seen := make(map[identityKey]bool, len(occs))
	out := occs[:0]
	for _, o := range occs {
		k := identityKey{o.Kind, o.Repository, o.Path, o.AbsolutePath, o.Commit, o.WorkingTree, o.HostRecorded}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, o)
	}
	SortOccurrences(out)
	return out
}

// SortOccurrences sorts deterministically by repository (none last), path,
// absolute path, committed before working tree, commit date (none last), and
// commit hash.
func SortOccurrences(o []Occurrence) {
	slices.SortStableFunc(o, func(a, b Occurrence) int {
		return cmp.Or(
			compareBool(a.Repository == "", b.Repository == ""),
			cmp.Compare(a.Repository, b.Repository),
			cmp.Compare(a.Path, b.Path),
			cmp.Compare(a.AbsolutePath, b.AbsolutePath),
			compareBool(a.WorkingTree, b.WorkingTree),
			compareDate(a.CommitDate, b.CommitDate),
			cmp.Compare(a.Commit, b.Commit),
		)
	})
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	default:
		return -1
	}
}

func compareDate(a, b time.Time) int {
	switch {
	case a.IsZero() || b.IsZero():
		return compareBool(a.IsZero(), b.IsZero())
	default:
		return a.Compare(b)
	}
}

// FormatLine renders one human location line, with two spaces between fields:
// "<repository>  <path>:<line>  <short commit>  <commit date>". A missing
// repository, commit or date is omitted; a working-tree location shows
// "working tree" in place of the commit fields; a legacy git location ends
// with "host not recorded". display replaces the path when non-empty (see
// DisambiguateDisplay). Every field passes through SanitizeDisplay.
func FormatLine(o Occurrence, line int, display string) string {
	fields := make([]string, 0, 5)
	if o.Repository != "" {
		fields = append(fields, SanitizeDisplay(o.Repository))
	}
	fields = append(fields, SanitizeDisplay(cmp.Or(display, o.Path))+":"+strconv.Itoa(line))
	switch {
	case o.WorkingTree:
		fields = append(fields, labelWorkingTree)
	case o.Commit != "":
		fields = append(fields, SanitizeDisplay(o.Commit[:min(len(o.Commit), shortCommitLen)]))
		if !o.CommitDate.IsZero() {
			fields = append(fields, o.CommitDate.UTC().Format(commitDateLayout))
		}
	}
	if o.Kind == "git" && !o.HostRecorded {
		fields = append(fields, labelHostNotRecord)
	}
	return strings.Join(fields, fieldSeparator)
}

// DisambiguateDisplay returns the path to display for each occurrence: its
// Path, or its AbsolutePath when its rendered line would otherwise collide
// with another occurrence's.
func DisambiguateDisplay(o []Occurrence) []string {
	counts := make(map[string]int, len(o))
	for _, occ := range o {
		counts[FormatLine(occ, 0, "")]++
	}
	out := make([]string, len(o))
	for i, occ := range o {
		out[i] = occ.Path
		if counts[FormatLine(occ, 0, "")] > 1 && occ.AbsolutePath != "" {
			out[i] = occ.AbsolutePath
		}
	}
	return out
}

// SanitizeDisplay makes untrusted text safe for a terminal. It escapes C0
// controls, DEL and invalid UTF-8 bytes as \xNN, and C1 controls and bidi
// controls as \u{NNNN}. Other printable Unicode is unchanged. Use it for
// human and TUI output only; JSON keeps exact bytes.
func SanitizeDisplay(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case (r >= 0x80 && r <= 0x9f) || isBidiControl(r):
			fmt.Fprintf(&b, `\u{%04x}`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func isBidiControl(r rune) bool {
	switch {
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
