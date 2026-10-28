package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Selection of report locations by recorded repository, namespace or path.
//
// Every form a selector is compared against is derived from stored
// Occurrence fields only and never parsed out of a URL or path, so a value
// that was not recorded is never presented as one (an unrecorded host is
// never shown as a host). Matching is exact or by whole path segment: there
// is no regexp, glob or LIKE.

const (
	selectorFlagRepo      = "repo"
	selectorFlagNamespace = "namespace"
	selectorFlagPath      = "path"
)

// sourcesHint is appended to every selection notice so the user can list the
// values a selector may take.
const sourcesHint = "Run 'titus report sources' to list"

// reportSelector holds the validated values of the repeatable --repo,
// --namespace and --path flags. A location is selected when any value of any
// flag selects it (union).
type reportSelector struct {
	repos      []string
	namespaces []string
	paths      []string
}

// newReportSelector validates the flag values. It runs before the datastore is
// opened, and an invalid value is a usage error that never falls back to
// unfiltered output.
func newReportSelector(repos, namespaces, paths []string) (*reportSelector, error) {
	// Repository and namespace forms are compared with "/" separators, so a
	// Windows folder value is normalized to the same form.
	repos, namespaces = toSlashAll(repos), toSlashAll(namespaces)
	for _, v := range repos {
		if err := validateSelectorValue(selectorFlagRepo, v, false); err != nil {
			return nil, err
		}
	}
	for _, v := range namespaces {
		if err := validateSelectorValue(selectorFlagNamespace, v, true); err != nil {
			return nil, err
		}
	}
	for _, v := range paths {
		if err := validateSelectorValue(selectorFlagPath, v, false); err != nil {
			return nil, err
		}
	}
	return &reportSelector{repos: repos, namespaces: namespaces, paths: paths}, nil
}

// toSlashAll returns vs with each value passed through filepath.ToSlash.
func toSlashAll(vs []string) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = filepath.ToSlash(v)
	}
	return out
}

// validateSelectorValue rejects an empty or whitespace-only value for any
// flag and, when segmented is set (--namespace only), a value with a trailing
// "/" or an empty segment. --repo is compared by exact equality against a
// recorded form, so any non-blank value is valid: a repository recorded as
// typed (for example "api/") must stay selectable. A leading "/" is valid (the
// absolute folder form). Spaces and commas inside a path are legal.
func validateSelectorValue(flagName, v string, segmented bool) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("--%s requires a non-empty value", flagName)
	}
	if segmented && !validSegments(v) {
		return fmt.Errorf("--%s value %q must not end with '/' or contain an empty path segment", flagName, v)
	}
	return nil
}

// validSegments reports whether v has no trailing "/" and no empty segment.
// One leading "/" is allowed.
func validSegments(v string) bool {
	body := strings.TrimPrefix(v, "/")
	if body == "" {
		return false
	}
	return !strings.HasSuffix(body, "/") && !strings.Contains(body, "//")
}

// active reports whether any selector value was given.
func (r *reportSelector) active() bool {
	return r != nil && (len(r.repos) > 0 || len(r.namespaces) > 0 || len(r.paths) > 0)
}

// filtersRepositories reports whether --repo or --namespace is active, the
// only selectors that can leave a host-less git record unselected.
func (r *reportSelector) filtersRepositories() bool {
	return r != nil && (len(r.repos) > 0 || len(r.namespaces) > 0)
}

// repositoryForms returns the displayed repository of o and, when o.Host is a
// prefix of it with a non-empty remainder, the repository without that host.
func repositoryForms(o types.Occurrence) []string {
	var forms []string
	if repo := filepath.ToSlash(o.Repository); repo != "" {
		forms = append(forms, repo)
		if o.Host != "" {
			if rest, ok := strings.CutPrefix(repo, o.Host+"/"); ok && rest != "" {
				forms = append(forms, rest)
			}
		}
	}
	return forms
}

// occurrenceForms returns the comparable repository forms of o, derived from
// stored fields only: the displayed repository, the repository without its
// recorded host, and the absolute folder.
func occurrenceForms(o types.Occurrence) []string {
	forms := repositoryForms(o)
	if folder := absoluteFolder(o); folder != "" {
		forms = append(forms, folder)
	}
	return forms
}

// absoluteFolder is o.AbsolutePath minus the trailing separator and o.Path,
// for a git record that stored both. It is independent of Host and
// HostRecorded: a local repository has a folder and no host.
func absoluteFolder(o types.Occurrence) string {
	if o.Kind != "git" || o.AbsolutePath == "" || o.Path == "" {
		return ""
	}
	return strings.TrimSuffix(filepath.ToSlash(o.AbsolutePath), "/"+o.Path)
}

// hostNotRecorded reports whether o is a git record stored without a host.
func hostNotRecorded(o types.Occurrence) bool {
	return o.Kind == "git" && !o.HostRecorded
}

// segmentPrefix reports whether f equals x or begins with x followed by "/":
// a whole-segment prefix.
func segmentPrefix(x, f string) bool {
	return f == x || strings.HasPrefix(f, x+"/")
}

// dropFirst returns x after its first "/", or "" when x has none.
func dropFirst(x string) string {
	_, rest, _ := strings.Cut(x, "/")
	return rest
}

// absoluteForm reports whether x is an absolute folder form after ToSlash: a
// leading "/" or a drive prefix such as "C:/". It is textual, so it behaves
// the same on every OS (filepath.IsAbs does not recognise "C:/" on unix). Such
// a selector has no host segment.
func absoluteForm(x string) bool {
	if strings.HasPrefix(x, "/") {
		return true
	}
	return len(x) >= 3 && x[1] == ':' && x[2] == '/' &&
		(x[0] >= 'a' && x[0] <= 'z' || x[0] >= 'A' && x[0] <= 'Z')
}

// selects reports whether o is selected by any value of any flag.
func (r *reportSelector) selects(o types.Occurrence) bool {
	if !r.active() {
		return true
	}
	forms := occurrenceForms(o)
	hnr := hostNotRecorded(o)

	for _, x := range r.repos {
		if repoSelects(x, o, forms, hnr) {
			return true
		}
	}
	for _, x := range r.namespaces {
		if namespaceSelects(x, o, forms, hnr) {
			return true
		}
	}
	for _, x := range r.paths {
		if x == o.Path || x == o.AbsolutePath {
			return true
		}
	}
	return false
}

// repoSelects: x equals any form of o. A record stored without a host is also
// selected when x, minus its first segment, equals the stored repository
// (the first segment is the host the user typed). An absolute folder form has
// no host segment, so it never takes that fallback. A recorded host is never
// selected by a different host.
func repoSelects(x string, o types.Occurrence, forms []string, hnr bool) bool {
	for _, f := range forms {
		if f == x {
			return true
		}
	}
	return hnr && o.Repository != "" && !absoluteForm(x) && dropFirst(x) == o.Repository
}

// namespaceSelects: x is a whole-segment prefix of any form of o, with the
// same host-less extension as repoSelects (skipped for an absolute folder form).
func namespaceSelects(x string, o types.Occurrence, forms []string, hnr bool) bool {
	for _, f := range forms {
		if segmentPrefix(x, f) {
			return true
		}
	}
	if hnr && o.Repository != "" && !absoluteForm(x) {
		if d := dropFirst(x); d != "" && segmentPrefix(d, o.Repository) {
			return true
		}
	}
	return false
}

// selectedBlob is the raw and selected locations of one blob.
type selectedBlob struct {
	raw      []types.Occurrence
	selected []types.Occurrence
}

// selectingStore narrows the locations every report writer reads to the
// selected ones. It overrides only GetOccurrences, so the writers keep their
// signatures and scan/enum output cannot reach it. Single-threaded.
type selectingStore struct {
	store.Store
	sel   *reportSelector
	cache map[types.BlobID]selectedBlob
}

// GetOccurrences returns only the selected locations of a blob.
func (s *selectingStore) GetOccurrences(id types.BlobID) ([]types.Occurrence, error) {
	b, err := s.load(id)
	if err != nil {
		return nil, err
	}
	return b.selected, nil
}

func (s *selectingStore) load(id types.BlobID) (selectedBlob, error) {
	if b, ok := s.cache[id]; ok {
		return b, nil
	}
	raw, err := s.Store.GetOccurrences(id)
	if err != nil {
		return selectedBlob{}, fmt.Errorf("reading locations of blob %s: %w", id.Hex(), err)
	}
	b := selectedBlob{raw: raw}
	for _, o := range raw {
		if s.sel.selects(o) {
			b.selected = append(b.selected, o)
		}
	}
	s.cache[id] = b
	return b, nil
}

// applySelection narrows findings and matches to the selected locations. It
// returns the store the writers must use, the retained findings and matches,
// and the number of host-less git locations that no selector selected. With no
// selector it returns its inputs unchanged, so unfiltered output is
// byte-identical.
func applySelection(s store.Store, sel *reportSelector, findings []*types.Finding,
	matches []*types.Match, ruleMap map[string]*types.Rule) (store.Store, []*types.Finding, []*types.Match, int, error) {
	if !sel.active() {
		return s, findings, matches, 0, nil
	}

	ss := &selectingStore{Store: s, sel: sel, cache: make(map[types.BlobID]selectedBlob)}

	unselectedHNR := 0
	counted := make(map[types.BlobID]bool)
	retained := make([]*types.Match, 0, len(matches))
	for _, m := range matches {
		b, err := ss.load(m.BlobID)
		if err != nil {
			return nil, nil, nil, 0, err
		}
		if !counted[m.BlobID] {
			counted[m.BlobID] = true
			unselectedHNR += countUnselectedHNR(b, sel)
		}
		if len(b.selected) > 0 {
			retained = append(retained, m)
		}
	}

	byFinding := buildFindingMatchMap(findings, retained, ruleMap)
	keptFindings := make([]*types.Finding, 0, len(findings))
	for _, f := range findings {
		if len(byFinding[f.ID]) > 0 {
			keptFindings = append(keptFindings, f)
		}
	}
	return ss, keptFindings, retained, unselectedHNR, nil
}

// countUnselectedHNR counts the host-less git locations of a blob that sel did
// not select. A location is one distinct occurrence of the blob.
func countUnselectedHNR(b selectedBlob, sel *reportSelector) int {
	n := 0
	for _, o := range b.raw {
		if hostNotRecorded(o) && !sel.selects(o) {
			n++
		}
	}
	return n
}

// selectionNotices returns the notices owed after a selected report, in
// emission order: the host-less locations that were not selected (only when
// --repo or --namespace is active) and the empty-selection notice.
func selectionNotices(sel *reportSelector, unselectedHNR, retainedFindings int) []string {
	if !sel.active() {
		return nil
	}
	var notices []string
	if sel.filtersRepositories() && unselectedHNR > 0 {
		notices = append(notices, fmt.Sprintf(
			"Note: %d location(s) recorded without a host were not selected. %s them.", unselectedHNR, sourcesHint))
	}
	if retainedFindings == 0 {
		notices = append(notices, fmt.Sprintf(
			"No findings matched the selection. %s the available sources.", sourcesHint))
	}
	return notices
}

// writeSelectionNotices writes notices after the report body. A human report
// carries them on stdout, sanitized for the terminal. JSON and SARIF carry
// them on stderr so stdout holds only the document.
func writeSelectionNotices(cmd *cobra.Command, human bool, notices []string) {
	for _, n := range notices {
		if human {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), types.SanitizeDisplay(n))
			continue
		}
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), n)
	}
}

// selectorValues returns the values a user can pass to --repo, --namespace and
// --path to select o, deduplicated in generation order. --repo values are every
// recorded repository form, including the absolute folder. --namespace values
// are the whole-segment prefixes of the displayed repository and of the
// host-less repository only; ancestors of the absolute folder are not listed,
// although a namespace equal to one still selects. Each listed value passes the
// flag's validation and selects at least one occurrence it came from. A record
// stored without a host lists its repository as stored and never receives a
// host-qualified form.
func selectorValues(o types.Occurrence) (repos, namespaces, paths []string) {
	add := func(list *[]string, v string, segmented bool) {
		if strings.TrimSpace(v) == "" || (segmented && !validSegments(v)) {
			return
		}
		for _, have := range *list {
			if have == v {
				return
			}
		}
		*list = append(*list, v)
	}

	for _, f := range occurrenceForms(o) {
		add(&repos, f, false)
	}

	for _, f := range repositoryForms(o) {
		for i := 1; i < len(f); i++ {
			if f[i] == '/' {
				add(&namespaces, f[:i], true)
			}
		}
	}

	add(&paths, o.Path, false)
	add(&paths, o.AbsolutePath, false)
	return repos, namespaces, paths
}
