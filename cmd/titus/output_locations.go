package main

import (
	"fmt"
	"io"
	"time"

	"github.com/fatih/color"
	"github.com/praetorian-inc/titus/pkg/sarif"
	"github.com/praetorian-inc/titus/pkg/store"
	"github.com/praetorian-inc/titus/pkg/types"
)

// Shared location output for scan and report, so the two cannot drift apart.

type jsonPos struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type jsonRange struct {
	Start jsonPos `json:"start"`
	End   jsonPos `json:"end"`
}

// jsonLocation is one location of a match in JSON output. All 7 keys are
// always present; an absent value is null. Values are exact bytes, never
// display-sanitized (encoding/json escapes control characters safely).
type jsonLocation struct {
	Repository   *string   `json:"repository"` // null for non-git
	Path         string    `json:"path"`
	Range        jsonRange `json:"range"`
	Commit       *string   `json:"commit"`
	CommitDate   *string   `json:"commit_date"` // RFC 3339
	AbsolutePath *string   `json:"absolute_path"`
	HostRecorded bool      `json:"host_recorded"`
}

// matchLocations returns every location of the blob a match was found in,
// merged, deduplicated and sorted by the store.
func matchLocations(s store.Store, m *types.Match) ([]types.Occurrence, error) {
	occs, err := s.GetOccurrences(m.BlobID)
	if err != nil {
		return nil, fmt.Errorf("reading locations of blob %s: %w", m.BlobID.Hex(), err)
	}
	return occs, nil
}

// blobLocations is every location of a blob plus whether the git history
// index recorded only some of them.
type blobLocations struct {
	occs      []types.Occurrence
	truncated bool
}

// loadBlobLocations reads the locations of a match's blob and its truncation
// flag, which lives on the blob's git provenance rows.
func loadBlobLocations(s store.Store, m *types.Match) (blobLocations, error) {
	occs, err := matchLocations(s, m)
	if err != nil {
		return blobLocations{}, err
	}
	provs, err := s.GetAllProvenance(m.BlobID)
	if err != nil {
		return blobLocations{}, fmt.Errorf("reading provenance of blob %s: %w", m.BlobID.Hex(), err)
	}
	return blobLocations{occs: occs, truncated: types.LocationsTruncated(provs)}, nil
}

// toJSONLocations converts occurrences to JSON locations, each carrying the
// match's range. It never returns nil, so JSON shows [] rather than null.
func toJSONLocations(m *types.Match, occs []types.Occurrence) []jsonLocation {
	src := m.Location.Source
	rng := jsonRange{
		Start: jsonPos{Line: src.Start.Line, Column: src.Start.Column},
		End:   jsonPos{Line: src.End.Line, Column: src.End.Column},
	}
	out := make([]jsonLocation, 0, len(occs))
	for _, o := range occs {
		loc := jsonLocation{
			Repository:   nonEmpty(o.Repository),
			Path:         o.Path,
			Range:        rng,
			Commit:       nonEmpty(o.Commit),
			AbsolutePath: nonEmpty(o.AbsolutePath),
			HostRecorded: o.HostRecorded,
		}
		if !o.CommitDate.IsZero() {
			loc.CommitDate = nonEmpty(o.CommitDate.UTC().Format(time.RFC3339))
		}
		out = append(out, loc)
	}
	return out
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// writeSARIF writes a SARIF 2.1.0 report with one result per location of
// every match. A match whose blob has no recorded location gets one result
// whose URI is the blob id. scoreFor may be nil.
func writeSARIF(w io.Writer, s store.Store, rules []*types.Rule, matches []*types.Match, scoreFor func(*types.Match) *types.Score) error {
	report := sarif.NewReport()
	for _, r := range rules {
		report.AddRule(r)
	}

	cache := make(map[types.BlobID]blobLocations)
	for _, m := range matches {
		locs, ok := cache[m.BlobID]
		if !ok {
			var err error
			if locs, err = loadBlobLocations(s, m); err != nil {
				return err
			}
			cache[m.BlobID] = locs
		}

		var score *types.Score
		if scoreFor != nil {
			score = scoreFor(m)
		}
		if len(locs.occs) == 0 {
			report.AddResultWithScore(m, m.BlobID.Hex(), score)
		}
		for _, o := range locs.occs {
			report.AddResultForOccurrence(m, o, score)
		}
		if locs.truncated {
			report.MarkLocationsTruncated()
		}
	}

	data, err := report.ToJSON()
	if err != nil {
		return fmt.Errorf("serializing SARIF: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing SARIF output: %w", err)
	}
	return nil
}

// writeLocationLines writes one indented human line per occurrence (see
// types.FormatLine), switching colliding lines to their absolute path. Every
// field is display-sanitized by FormatLine. style may be nil for plain text.
func writeLocationLines(w io.Writer, line int, occs []types.Occurrence, style *color.Color) {
	display := types.DisambiguateDisplay(occs)
	for i, o := range occs {
		text := types.FormatLine(o, line, display[i])
		if style != nil {
			text = style.Sprint(text)
		}
		_, _ = fmt.Fprintf(w, "    %s\n", text)
	}
}

// writeLocationsTruncated writes the truncation marker line after a location
// list, and nothing when truncated is false. style may be nil for plain text.
func writeLocationsTruncated(w io.Writer, truncated bool, style *color.Color) {
	if !truncated {
		return
	}
	text := types.LocationsTruncatedNotice
	if style != nil {
		text = style.Sprint(text)
	}
	_, _ = fmt.Fprintf(w, "    %s\n", text)
}
