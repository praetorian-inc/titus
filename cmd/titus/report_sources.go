package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/praetorian-inc/titus/pkg/repoid"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/spf13/cobra"
)

const (
	sourcesScopeFindings = "findings"
	sourcesScopeAll      = "all"

	unselectableReason = "no repository or path recorded"
)

// sourcesSelectorHelp is shared by both source commands: how a listed value
// is passed back to the report.
const sourcesSelectorHelp = `Every value is a selector for the report: pass a repository to --repo, a
namespace to --namespace and a path to --path. A repository is listed with
its host (github.com/acme/api) and without it (acme/api); either form
selects. A location recorded without a host is listed as stored, marked
(host not recorded), and has no host-qualified form. Such a location cannot
be tied to one host, so a host-qualified --repo or --namespace value may also
select it. This limitation comes from datastores written by earlier versions
and goes away for a source once it is scanned again.

A repository written as an absolute folder (/work/a/api) is also a --repo
and --namespace form, not a --path form. Only locations that recorded a
folder produce it: working-tree copies and repositories without a remote.
Repositories that display the same value are told apart by their folders.`

const sourcesLong = `List the values that select the findings the report covers.

Scope: only the sources of current findings. Rejected findings are left out
unless --show-rejected is set, exactly as in 'titus report'. A source with no
finding is not listed; use 'titus report sources all' for every recorded
source.

` + sourcesSelectorHelp + `

Output is sorted and deduplicated. Use --format json for the copyable raw
values. The command lists recorded values only and does not reconstruct scan
targets.`

const sourcesAllLong = `List every source recorded in the datastore, including sources with no findings.

Scope: all recorded sources. --show-rejected has no effect here. A record
that has no repository, namespace or path to select is listed as an
unselectable record with its kind.

` + sourcesSelectorHelp + `

Under this command an absolute folder appears only where a location row
recorded one.

Output is sorted and deduplicated. Use --format json for the copyable raw
values. The command lists recorded values only and does not reconstruct scan
targets.`

var (
	sourcesFormat string

	sourcesCmd = &cobra.Command{
		Use:   "sources",
		Short: "List the values that select the reported findings",
		Long:  sourcesLong,
		Args:  cobra.NoArgs,
		RunE:  runSources,
	}

	sourcesAllCmd = &cobra.Command{
		Use:   "all",
		Short: "List every recorded source, including sources with no findings",
		Long:  sourcesAllLong,
		Args:  cobra.NoArgs,
		RunE:  runSourcesAll,
	}
)

func init() {
	sourcesCmd.PersistentFlags().StringVar(&sourcesFormat, "format", "human", "Output format: human, json")
	sourcesCmd.AddCommand(sourcesAllCmd)
	reportCmd.AddCommand(sourcesCmd)
}

// sourceRepo is one repository selector value.
type sourceRepo struct {
	Value        string `json:"value"`
	Kind         string `json:"kind"`
	Host         string `json:"host"`
	HostRecorded bool   `json:"host_recorded"`
}

// sourceNamespace is one namespace selector value.
type sourceNamespace struct {
	Value        string `json:"value"`
	HostRecorded bool   `json:"host_recorded"`
}

// sourcePath is one path selector value. Absolute is true for a recorded
// absolute path.
type sourcePath struct {
	Value    string `json:"value"`
	Absolute bool   `json:"absolute"`
}

// sourceUnselectable is a record that yields no selector value.
type sourceUnselectable struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// sourcesResult is the JSON document of both commands. Its lists are never
// nil, so an empty list encodes as [].
type sourcesResult struct {
	Scope        string               `json:"scope"`
	Repos        []sourceRepo         `json:"repos"`
	Namespaces   []sourceNamespace    `json:"namespaces"`
	Paths        []sourcePath         `json:"paths"`
	Unselectable []sourceUnselectable `json:"unselectable"`
}

// sourceSet collects deduplicated entries. Entries are comparable structs, so
// each map is its own set; equal text with a different host record stays two
// entries.
type sourceSet struct {
	repos        map[sourceRepo]struct{}
	namespaces   map[sourceNamespace]struct{}
	paths        map[sourcePath]struct{}
	unselectable map[sourceUnselectable]struct{}
}

func newSourceSet() *sourceSet {
	return &sourceSet{
		repos:        map[sourceRepo]struct{}{},
		namespaces:   map[sourceNamespace]struct{}{},
		paths:        map[sourcePath]struct{}{},
		unselectable: map[sourceUnselectable]struct{}{},
	}
}

// add records the selector values of o. A credentialed repository is redacted
// first, so no value carries userinfo.
func (ss *sourceSet) add(o types.Occurrence) {
	o.Repository = repoid.RedactUserinfo(o.Repository)
	repos, namespaces, paths := selectorValues(o)
	if len(repos)+len(namespaces)+len(paths) == 0 {
		ss.unselectable[sourceUnselectable{Kind: o.Kind, Reason: unselectableReason}] = struct{}{}
		return
	}
	for _, v := range repos {
		ss.repos[sourceRepo{Value: v, Kind: o.Kind, Host: o.Host, HostRecorded: o.HostRecorded}] = struct{}{}
	}
	for _, v := range namespaces {
		ss.namespaces[sourceNamespace{Value: v, HostRecorded: o.HostRecorded}] = struct{}{}
	}
	for _, v := range paths {
		ss.paths[sourcePath{Value: v, Absolute: v == o.AbsolutePath}] = struct{}{}
	}
}

// sortedKeys returns the keys of set ordered by less.
func sortedKeys[K comparable](set map[K]struct{}, compare func(a, b K) int) []K {
	keys := make([]K, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, compare)
	return keys
}

// compareRecorded orders false before true: a host-less entry sorts first.
func compareRecorded(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	default:
		return 1
	}
}

// result returns the sorted, non-nil document for scope.
func (ss *sourceSet) result(scope string) sourcesResult {
	return sourcesResult{
		Scope: scope,
		Repos: sortedKeys(ss.repos, func(a, b sourceRepo) int {
			return cmp.Or(cmp.Compare(a.Value, b.Value), compareRecorded(a.HostRecorded, b.HostRecorded),
				cmp.Compare(a.Host, b.Host), cmp.Compare(a.Kind, b.Kind))
		}),
		Namespaces: sortedKeys(ss.namespaces, func(a, b sourceNamespace) int {
			return cmp.Or(cmp.Compare(a.Value, b.Value), compareRecorded(a.HostRecorded, b.HostRecorded))
		}),
		Paths: sortedKeys(ss.paths, func(a, b sourcePath) int {
			return cmp.Or(cmp.Compare(a.Value, b.Value), compareRecorded(!a.Absolute, !b.Absolute))
		}),
		Unselectable: sortedKeys(ss.unselectable, func(a, b sourceUnselectable) int {
			return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Reason, b.Reason))
		}),
	}
}

func runSources(cmd *cobra.Command, args []string) error {
	if err := checkSourcesFormat(); err != nil {
		return err
	}
	s, err := openReportStore(reportDatastore)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	_, matches, _, err := loadReportScope(s)
	if err != nil {
		return err
	}

	set := newSourceSet()
	seen := make(map[types.BlobID]struct{})
	for _, m := range matches {
		if _, ok := seen[m.BlobID]; ok {
			continue
		}
		seen[m.BlobID] = struct{}{}
		occurrences, err := s.GetOccurrences(m.BlobID)
		if err != nil {
			return fmt.Errorf("retrieving locations: %w", err)
		}
		for _, o := range occurrences {
			set.add(o)
		}
	}
	return writeSources(cmd.OutOrStdout(), set.result(sourcesScopeFindings))
}

func runSourcesAll(cmd *cobra.Command, args []string) error {
	if err := checkSourcesFormat(); err != nil {
		return err
	}
	s, err := openReportStore(reportDatastore)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	return writeSourcesAll(cmd.OutOrStdout(), s)
}

func writeSourcesAll(out io.Writer, s store.Store) error {
	records, err := s.ListSources()
	if err != nil {
		return fmt.Errorf("listing sources: %w", err)
	}
	set := newSourceSet()
	for _, r := range records {
		set.add(types.Occurrence{
			Kind:         r.Kind,
			Repository:   r.Repository,
			Host:         r.Host,
			HostRecorded: r.HostRecorded,
			Path:         r.Path,
			AbsolutePath: r.AbsolutePath,
		})
	}
	return writeSources(out, set.result(sourcesScopeAll))
}

// checkSourcesFormat rejects every format the source commands do not write,
// SARIF included, before the datastore is opened.
func checkSourcesFormat() error {
	switch sourcesFormat {
	case "human", "json":
		return nil
	case "sarif":
		return fmt.Errorf("output format sarif is not supported by the sources commands: use human or json")
	default:
		return fmt.Errorf("unknown output format: %s", sourcesFormat)
	}
}

func writeSources(out io.Writer, res sourcesResult) error {
	if sourcesFormat == "json" {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(res)
	}
	return writeSourcesHuman(out, res)
}

// writeSourcesHuman prints the lists with every value sanitized for the
// terminal. A value of a git record stored without a host is marked as
// FormatLine marks it.
func writeSourcesHuman(out io.Writer, res sourcesResult) error {
	var err error
	line := func(format string, args ...any) {
		if err == nil {
			_, err = fmt.Fprintf(out, format+"\n", args...)
		}
	}
	mark := func(v string, recorded bool) string {
		v = types.SanitizeDisplay(v)
		if !recorded {
			v += "  (" + types.LabelHostNotRecorded + ")"
		}
		return v
	}

	line("Repositories (--repo)")
	for _, r := range res.Repos {
		line("  %s", mark(r.Value, r.HostRecorded || r.Kind != "git"))
	}
	line("")
	line("Namespaces (--namespace)")
	for _, n := range res.Namespaces {
		line("  %s", mark(n.Value, n.HostRecorded))
	}
	line("")
	line("Paths (--path)")
	for _, p := range res.Paths {
		line("  %s", types.SanitizeDisplay(p.Value))
	}
	if res.Scope == sourcesScopeAll {
		line("")
		line("Unselectable records")
		for _, u := range res.Unselectable {
			line("  %s  %s", types.SanitizeDisplay(u.Kind), u.Reason)
		}
	}
	return err
}
