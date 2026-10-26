package explore

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/praetorian-inc/titus/pkg/types"
)

// detailsPane shows match details for the selected finding.
type detailsPane struct {
	finding *findingRow
	// repoFilter is the Repository facet selection; empty shows every location.
	repoFilter map[string]bool
	// visibleMatchIdx holds the indexes into finding.Matches of the matches
	// navigable under repoFilter. matchCursor indexes this slice.
	visibleMatchIdx []int
	matchCursor     int
	width           int
	height          int
	offset          int // scroll offset for content
	focused         bool
	// cache holds the rendered location block of the selected match. It is a
	// pointer so the copies bubbletea makes of the pane share one cache.
	cache *locationsCache
}

// locationsCache holds the rendered location and source lines of one match:
// the only part of the pane whose size grows with the data. Every input the
// lines depend on is part of the key, so in-place edits elsewhere in the pane
// (annotations, comments, the match cursor) need no invalidation. The filter
// is keyed by value, not by a counter, so pane copies that share the cache
// can never read lines rendered under another copy's filter.
type locationsCache struct {
	match  *matchRow
	filter map[string]bool // a private clone of the repo filter
	width  int
	lines  []string
}

func newDetailsPane() detailsPane {
	return detailsPane{cache: &locationsCache{}}
}

// setFinding shows f under the current repo filter, starting on its first
// visible match.
func (dp *detailsPane) setFinding(f *findingRow) {
	dp.finding = f
	dp.matchCursor = 0
	dp.offset = 0
	dp.recomputeVisibleMatches()
}

// setRepoFilter sets the Repository facet selection used to narrow locations
// and match navigation. Like setFinding, it returns the pane to the first
// visible match at the top, so the two calls give the same result in either
// order. Callers pass a fresh map and never modify it afterwards.
func (dp *detailsPane) setRepoFilter(sel map[string]bool) {
	dp.repoFilter = sel
	dp.matchCursor = 0
	dp.offset = 0
	dp.recomputeVisibleMatches()
}

// recomputeVisibleMatches lists the matches h/l can visit: every match when no
// repository is selected, otherwise those with at least one visible location.
func (dp *detailsPane) recomputeVisibleMatches() {
	dp.visibleMatchIdx = dp.visibleMatchIdx[:0]
	if dp.finding == nil {
		return
	}
	for i, m := range dp.finding.Matches {
		if dp.hasVisibleLocation(m) {
			dp.visibleMatchIdx = append(dp.visibleMatchIdx, i)
		}
	}
}

// hasVisibleLocation reports whether m is navigable under repoFilter, without
// copying its occurrences. A match whose locations failed to load or were
// truncated stays navigable, so its warning is not hidden by a facet (S1).
func (dp *detailsPane) hasVisibleLocation(m *matchRow) bool {
	if len(dp.repoFilter) == 0 || matchLocationsUnknown(m) {
		return true
	}
	return slices.ContainsFunc(m.Occurrences, func(o types.Occurrence) bool {
		k := facetKey(o)
		return k != "" && dp.repoFilter[k]
	})
}

// nextMatch moves to the next visible match, if there is one.
func (dp *detailsPane) nextMatch() {
	if dp.matchCursor < len(dp.visibleMatchIdx)-1 {
		dp.matchCursor++
		dp.offset = 0
	}
}

func (dp detailsPane) selectedMatch() *matchRow {
	if dp.finding == nil || dp.matchCursor < 0 || dp.matchCursor >= len(dp.visibleMatchIdx) {
		return nil
	}
	return dp.finding.Matches[dp.visibleMatchIdx[dp.matchCursor]]
}

func (dp detailsPane) Update(msg tea.Msg) (detailsPane, tea.Cmd) {
	if !dp.focused {
		return dp, nil
	}

	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return dp, nil
	}

	switch {
	case keyMatches(keyMsg, defaultKeys.Up):
		dp.offset = max(0, min(dp.offset, dp.maxOffset())-1)
	case keyMatches(keyMsg, defaultKeys.Down):
		dp.offset = min(dp.offset+1, dp.maxOffset())
	case keyMatches(keyMsg, defaultKeys.Left):
		if dp.matchCursor > 0 {
			dp.matchCursor--
			dp.offset = 0
		}
	case keyMatches(keyMsg, defaultKeys.Right):
		dp.nextMatch()
	case keyMatches(keyMsg, defaultKeys.Home):
		dp.offset = 0
	case keyMatches(keyMsg, defaultKeys.PageDown):
		dp.offset = min(dp.offset+dp.visibleRows(), dp.maxOffset())
	case keyMatches(keyMsg, defaultKeys.PageUp):
		dp.offset = max(0, min(dp.offset, dp.maxOffset())-dp.visibleRows())
	}

	return dp, nil
}

// maxOffset is the largest scroll offset that still fills the pane, so
// scrolling past the end never accumulates hidden offset.
func (dp detailsPane) maxOffset() int {
	return max(0, dp.content().len()-dp.visibleRows())
}

func (dp detailsPane) View() string {
	if dp.width <= 0 || dp.height <= 0 {
		return ""
	}

	contentWidth := max(0, dp.width-4)
	c := dp.content()

	// Apply scroll offset
	offset := min(dp.offset, max(0, c.len()-1))
	visibleLines := c.window(offset, dp.visibleRows())

	var b strings.Builder
	for i, line := range visibleLines {
		b.WriteString(padRight(ansi.Truncate(line, contentWidth, ""), contentWidth))
		if i < len(visibleLines)-1 {
			b.WriteString("\n")
		}
	}
	// Fill empty
	for i := len(visibleLines); i < dp.visibleRows(); i++ {
		b.WriteString(strings.Repeat(" ", contentWidth))
		if i < dp.visibleRows()-1 {
			b.WriteString("\n")
		}
	}

	title := titleStyle.Render(" Details ")

	borderStyle := inactiveBorderStyle
	if dp.focused {
		borderStyle = activeBorderStyle
	}

	content := borderStyle.
		Width(dp.width - 2).
		Height(dp.height - 3).
		Render(b.String())

	return lipgloss.JoinVertical(lipgloss.Left, title, content)
}

// paneContent is the pane's lines before scrolling and clipping, kept in
// parts so the large cached location block is never copied.
type paneContent [][]string

func (c paneContent) len() int {
	n := 0
	for _, part := range c {
		n += len(part)
	}
	return n
}

// window returns at most n lines starting at line off.
func (c paneContent) window(off, n int) []string {
	var out []string
	for _, part := range c {
		if off >= len(part) {
			off -= len(part)
			continue
		}
		take := part[off:min(len(part), off+n-len(out))]
		out = append(out, take...)
		off = 0
		if len(out) == n {
			break
		}
	}
	return out
}

// content returns the pane's lines in parts. Only the location block is
// cached; the parts around it are bounded in size and rebuilt per call so
// in-place edits (annotations, comments) show at once.
func (dp detailsPane) content() paneContent {
	if dp.finding == nil {
		return paneContent{{"  No finding selected"}}
	}

	contentWidth := max(0, dp.width-4)
	head := renderFindingHeader(dp.finding, contentWidth)

	m := dp.selectedMatch()
	if m == nil {
		return paneContent{append(head, "  No matches")}
	}
	head = append(head,
		fmt.Sprintf("  %s", headerRowStyle.Render(fmt.Sprintf("Match %d/%d (h/l to navigate)", dp.matchCursor+1, len(dp.visibleMatchIdx)))),
		"  "+strings.Repeat("─", min(40, max(0, contentWidth-4))))
	return paneContent{head, dp.matchBody(m, contentWidth), renderMatchTail(m, contentWidth)}
}

// matchBody returns the cached location and source lines of m, rendering them
// only when the match, the repo filter or the width changed.
func (dp detailsPane) matchBody(m *matchRow, width int) []string {
	c := dp.cache
	if c == nil {
		return renderMatchBody(m, dp.repoFilter, width)
	}
	if c.match != m || c.width != width || !maps.Equal(c.filter, dp.repoFilter) {
		*c = locationsCache{match: m, filter: maps.Clone(dp.repoFilter), width: width,
			lines: renderMatchBody(m, dp.repoFilter, width)}
	}
	return c.lines
}

// renderFindingHeader renders the finding-level lines above the match.
func renderFindingHeader(f *findingRow, contentWidth int) []string {
	var lines []string

	// Finding header
	lines = append(lines, fmt.Sprintf("  %s %s",
		fieldLabelStyle.Render("Rule:"),
		fieldValueStyle.Render(types.SanitizeDisplay(fmt.Sprintf("%s (%s)", f.RuleName, f.RuleID)))))

	if len(f.Categories) > 0 {
		lines = append(lines, fmt.Sprintf("  %s %s",
			fieldLabelStyle.Render("Categories:"),
			fieldValueStyle.Render(types.SanitizeDisplay(strings.Join(f.Categories, ", ")))))
	}

	// Groups with named groups if available
	for i, g := range f.Groups {
		label := fmt.Sprintf("Group %d:", i+1)
		val := sanitizeForDisplay(g)
		labelWidth := len(label) + 3 // "  " + label + " "
		wrapped := wrapLine(val, max(1, contentWidth-labelWidth))
		indent := strings.Repeat(" ", labelWidth)
		for j, line := range wrapped {
			if j == 0 {
				lines = append(lines, "  "+fieldLabelStyle.Render(label)+" "+snippetMatchStyle.Render(line))
			} else {
				lines = append(lines, indent+snippetMatchStyle.Render(line))
			}
		}
	}

	if f.AnnotationStatus != "" {
		lines = append(lines, fmt.Sprintf("  %s %s",
			fieldLabelStyle.Render("Status:"),
			renderAnnotationStatus(f.AnnotationStatus)))
	}
	if f.Comment != "" {
		lines = append(lines, fmt.Sprintf("  %s %s",
			fieldLabelStyle.Render("Comment:"),
			fieldValueStyle.Render(types.SanitizeDisplay(f.Comment))))
	}

	return append(lines, "")
}

func renderMatchDetails(m *matchRow, sel map[string]bool, maxWidth int) []string {
	return slices.Concat(renderMatchBody(m, sel, maxWidth), renderMatchTail(m, maxWidth))
}

// renderMatchBody renders the parts of a match that grow with the data: its
// locations and the details of its extended sources.
func renderMatchBody(m *matchRow, sel map[string]bool, maxWidth int) []string {
	return append(renderLocations(m, sel, maxWidth), renderSourceDetails(m.Provenance, sel)...)
}

// renderMatchTail renders the bounded per-match lines below the locations.
func renderMatchTail(m *matchRow, maxWidth int) []string {
	var lines []string

	// Blob
	lines = append(lines, fmt.Sprintf("  %s %s",
		fieldLabelStyle.Render("Blob:"),
		fieldValueStyle.Render(m.BlobID.Hex())))

	// Range of the match within the blob
	if m.Location.Source.Start.Line > 0 {
		lines = append(lines, fmt.Sprintf("  %s %d:%d - %d:%d (bytes %d-%d)",
			fieldLabelStyle.Render("Range:"),
			m.Location.Source.Start.Line, m.Location.Source.Start.Column,
			m.Location.Source.End.Line, m.Location.Source.End.Column,
			m.Location.Offset.Start, m.Location.Offset.End))
	}

	// Validation
	if m.ValidationStatus != "" {
		valLine := fmt.Sprintf("  %s %s",
			fieldLabelStyle.Render("Validation:"),
			renderValidationStatus(m.ValidationStatus))
		if m.Confidence > 0 {
			valLine += fmt.Sprintf(" (%.2f)", m.Confidence)
		}
		if m.Message != "" {
			valLine += " - " + types.SanitizeDisplay(m.Message)
		}
		lines = append(lines, valLine)
	}

	// Named groups
	if len(m.NamedGroups) > 0 {
		lines = append(lines, fmt.Sprintf("  %s", fieldLabelStyle.Render("Named Groups:")))
		for name, val := range m.NamedGroups {
			label := types.SanitizeDisplay(name) + ":"
			sanitized := sanitizeForDisplay(val)
			labelWidth := ansi.StringWidth(label) + 5 // "    " + label + " "
			wrapped := wrapLine(sanitized, max(1, maxWidth-labelWidth))
			indent := strings.Repeat(" ", labelWidth)
			for j, line := range wrapped {
				if j == 0 {
					lines = append(lines, "    "+fieldLabelStyle.Render(label)+" "+snippetMatchStyle.Render(line))
				} else {
					lines = append(lines, indent+snippetMatchStyle.Render(line))
				}
			}
		}
	}

	// Match annotation
	if m.AnnotationStatus != "" {
		lines = append(lines, fmt.Sprintf("  %s %s",
			fieldLabelStyle.Render("Status:"),
			renderAnnotationStatus(m.AnnotationStatus)))
	}
	if m.Comment != "" {
		lines = append(lines, fmt.Sprintf("  %s %s",
			fieldLabelStyle.Render("Comment:"),
			fieldValueStyle.Render(types.SanitizeDisplay(m.Comment))))
	}

	// Snippet
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("  %s", fieldLabelStyle.Render("Snippet:")))

	snippetWidth := maxWidth - 6
	before := strings.TrimRight(sanitizeForDisplay(m.Snippet.Before), "\n\r")
	matching := sanitizeForDisplay(m.Snippet.Matching)
	after := strings.TrimLeft(sanitizeForDisplay(m.Snippet.After), "\n\r")

	// Render snippet lines
	for _, line := range strings.Split(before, "\n") {
		if line != "" {
			lines = append(lines, "    "+snippetContextStyle.Render(truncateString(line, snippetWidth)))
		}
	}
	for _, line := range strings.Split(matching, "\n") {
		lines = append(lines, "    "+snippetMatchStyle.Render(truncateString(line, snippetWidth)))
	}
	for _, line := range strings.Split(after, "\n") {
		if line != "" {
			lines = append(lines, "    "+snippetContextStyle.Render(truncateString(line, snippetWidth)))
		}
	}

	return lines
}

// renderLocations renders the "Locations N:" heading and one line per location
// visible under sel, using the shared human line format. Each line is
// sanitized, then wrapped with a 6-space continuation indent. When the
// locations could not be loaded, it says so instead of showing a count.
func renderLocations(m *matchRow, sel map[string]bool, maxWidth int) []string {
	wrapWidth := max(1, maxWidth-6)
	var lines []string
	appendWrapped := func(text string) {
		for j, part := range wrapLine(text, wrapWidth) {
			indent := "      "
			if j == 0 {
				indent = "    "
			}
			lines = append(lines, indent+fieldValueStyle.Render(part))
		}
	}

	if m.LocationsErr != nil {
		lines = append(lines, "  "+fieldLabelStyle.Render("Locations unavailable:"))
		appendWrapped(types.SanitizeDisplay(m.LocationsErr.Error()))
	} else {
		vis := visibleOccurrences(m.Occurrences, sel)
		disp := types.DisambiguateDisplay(vis)
		lines = append(lines, "  "+fieldLabelStyle.Render(fmt.Sprintf("Locations %d:", len(vis))))
		for i, o := range vis {
			appendWrapped(types.SanitizeDisplay(types.FormatLine(o, m.Location.Source.Start.Line, disp[i])))
		}
	}
	if m.ProvenanceErr != nil {
		// Without provenance the truncation notice and the extended-source
		// details below cannot be shown, so say why. Both lines wrap, so a
		// narrow pane never clips the warning.
		appendWrapped("Provenance unavailable; locations may be incomplete:")
		appendWrapped(types.SanitizeDisplay(m.ProvenanceErr.Error()))
	}
	if types.LocationsTruncated(m.Provenance) {
		appendWrapped(types.LocationsTruncatedNotice)
	}
	return lines
}

// extendedFields lists the extended-source payload fields shown below the
// locations. The location line already carries the source and path.
var extendedFields = []struct{ label, key string }{
	{"Title:", "title"},
	{"URL:", "url"},
	{"Team:", "team"},
	{"Project:", "project"},
	{"Space:", "space"},
	{"Channel:", "channel"},
	{"Author:", "author"},
}

// renderSourceDetails renders the identifying fields of each extended-source
// provenance whose source is visible under sel. Every value is sanitized.
func renderSourceDetails(provs []types.Provenance, sel map[string]bool) []string {
	var lines []string
	field := func(label, value string) {
		lines = append(lines, fmt.Sprintf("  %s %s",
			fieldLabelStyle.Render(label),
			fieldValueStyle.Render(types.SanitizeDisplay(value))))
	}
	for _, prov := range provs {
		p, ok := prov.(types.ExtendedProvenance)
		if !ok {
			continue
		}
		if source, _ := p.Payload["source"].(string); len(sel) > 0 && !sel[source] {
			continue
		}
		if id := extendedID(p.Payload); id != "" {
			field(extendedIDLabel(p.Payload["entityType"]), id)
		}
		for _, f := range extendedFields {
			if v, _ := p.Payload[f.key].(string); v != "" {
				field(f.label, v)
			}
		}
	}
	return lines
}

func extendedID(payload map[string]any) string {
	if id, _ := payload["identifier"].(string); id != "" {
		return id
	}
	id, _ := payload["pageID"].(string)
	return id
}

func extendedIDLabel(entityType any) string {
	switch entityType {
	case "issue":
		return "Issue:"
	case "document":
		return "Document:"
	case "projectUpdate":
		return "Update:"
	default:
		return "ID:"
	}
}

// wrapLine splits a string into lines of at most maxWidth terminal cells.
// Existing newlines in the input are respected. Wrapping by display width,
// not by rune, keeps wide characters (CJK, emoji) from overflowing the pane,
// where the final clip would otherwise drop the end of the line.
func wrapLine(s string, maxWidth int) []string {
	if maxWidth <= 0 {
		return []string{s}
	}
	return strings.Split(ansi.Hardwrap(s, maxWidth, true), "\n")
}

func (dp detailsPane) visibleRows() int {
	return max(1, dp.height-4)
}

func (dp *detailsPane) setSize(w, h int) {
	dp.width = w
	dp.height = h
}
