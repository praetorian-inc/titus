package explore

import (
	"fmt"
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
}

func newDetailsPane() detailsPane {
	return detailsPane{}
}

func (dp *detailsPane) setFinding(f *findingRow) {
	dp.finding = f
	dp.matchCursor = 0
	dp.offset = 0
	dp.recomputeVisibleMatches()
}

// setRepoFilter sets the Repository facet selection used to narrow locations
// and match navigation. Call it before setFinding when the selection changes.
func (dp *detailsPane) setRepoFilter(sel map[string]bool) {
	dp.repoFilter = sel
	dp.recomputeVisibleMatches()
	dp.matchCursor = max(0, min(dp.matchCursor, len(dp.visibleMatchIdx)-1))
}

// recomputeVisibleMatches lists the matches h/l can visit: every match when no
// repository is selected, otherwise those with at least one visible location.
func (dp *detailsPane) recomputeVisibleMatches() {
	dp.visibleMatchIdx = dp.visibleMatchIdx[:0]
	if dp.finding == nil {
		return
	}
	for i, m := range dp.finding.Matches {
		if len(dp.repoFilter) == 0 || len(visibleOccurrences(m.Occurrences, dp.repoFilter)) > 0 {
			dp.visibleMatchIdx = append(dp.visibleMatchIdx, i)
		}
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
		if dp.matchCursor < len(dp.visibleMatchIdx)-1 {
			dp.matchCursor++
			dp.offset = 0
		}
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
	return max(0, len(dp.contentLines())-dp.visibleRows())
}

func (dp detailsPane) View() string {
	if dp.width <= 0 || dp.height <= 0 {
		return ""
	}

	contentWidth := dp.width - 4
	lines := dp.contentLines()

	// Apply scroll offset
	if dp.offset >= len(lines) {
		dp.offset = max(0, len(lines)-1)
	}
	visibleLines := lines
	if dp.offset < len(visibleLines) {
		visibleLines = visibleLines[dp.offset:]
	}
	if len(visibleLines) > dp.visibleRows() {
		visibleLines = visibleLines[:dp.visibleRows()]
	}

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

// contentLines renders every line of the pane before scrolling and clipping.
func (dp detailsPane) contentLines() []string {
	if dp.finding == nil {
		return []string{"  No finding selected"}
	}

	contentWidth := dp.width - 4
	f := dp.finding
	var lines []string

	// Finding header
	lines = append(lines, fmt.Sprintf("  %s %s",
		fieldLabelStyle.Render("Rule:"),
		fieldValueStyle.Render(fmt.Sprintf("%s (%s)", f.RuleName, f.RuleID))))

	if len(f.Categories) > 0 {
		lines = append(lines, fmt.Sprintf("  %s %s",
			fieldLabelStyle.Render("Categories:"),
			fieldValueStyle.Render(strings.Join(f.Categories, ", "))))
	}

	// Groups with named groups if available
	for i, g := range f.Groups {
		label := fmt.Sprintf("Group %d:", i+1)
		val := sanitizeForDisplay(g)
		labelWidth := len(label) + 3 // "  " + label + " "
		wrapped := wrapLine(val, max(20, contentWidth-labelWidth))
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
			fieldValueStyle.Render(f.Comment)))
	}

	lines = append(lines, "")

	// Match details
	m := dp.selectedMatch()
	if m == nil {
		return append(lines, "  No matches")
	}
	lines = append(lines, fmt.Sprintf("  %s",
		headerRowStyle.Render(fmt.Sprintf("Match %d/%d (h/l to navigate)", dp.matchCursor+1, len(dp.visibleMatchIdx)))))
	lines = append(lines, "  "+strings.Repeat("─", min(40, contentWidth-4)))
	return append(lines, renderMatchDetails(m, dp.repoFilter, contentWidth)...)
}

func renderMatchDetails(m *matchRow, sel map[string]bool, maxWidth int) []string {
	lines := renderLocations(m, sel, maxWidth)
	lines = append(lines, renderSourceDetails(m.Provenance, sel)...)

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
			valLine += " - " + m.Message
		}
		lines = append(lines, valLine)
	}

	// Named groups
	if len(m.NamedGroups) > 0 {
		lines = append(lines, fmt.Sprintf("  %s", fieldLabelStyle.Render("Named Groups:")))
		for name, val := range m.NamedGroups {
			label := name + ":"
			sanitized := sanitizeForDisplay(val)
			labelWidth := len(label) + 5 // "    " + label + " "
			wrapped := wrapLine(sanitized, max(20, maxWidth-labelWidth))
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
			fieldValueStyle.Render(m.Comment)))
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
// sanitized, then wrapped with a 6-space continuation indent.
func renderLocations(m *matchRow, sel map[string]bool, maxWidth int) []string {
	vis := visibleOccurrences(m.Occurrences, sel)
	disp := types.DisambiguateDisplay(vis)
	lines := []string{"  " + fieldLabelStyle.Render(fmt.Sprintf("Locations %d:", len(vis)))}
	wrapWidth := max(20, maxWidth-6)
	for i, o := range vis {
		text := types.SanitizeDisplay(types.FormatLine(o, m.Location.Source.Start.Line, disp[i]))
		for j, part := range wrapLine(text, wrapWidth) {
			indent := "      "
			if j == 0 {
				indent = "    "
			}
			lines = append(lines, indent+fieldValueStyle.Render(part))
		}
	}
	if types.LocationsTruncated(m.Provenance) {
		for j, part := range wrapLine(types.LocationsTruncatedNotice, wrapWidth) {
			indent := "      "
			if j == 0 {
				indent = "    "
			}
			lines = append(lines, indent+fieldValueStyle.Render(part))
		}
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

// wrapLine splits a string into lines of at most maxWidth runes. Existing
// newlines in the input are respected. Splitting by rune keeps multi-byte
// characters whole; wide characters may still exceed maxWidth cells, which
// the pane's final ansi.Truncate clips.
func wrapLine(s string, maxWidth int) []string {
	if maxWidth <= 0 {
		return []string{s}
	}
	var result []string
	for _, line := range strings.Split(s, "\n") {
		runes := []rune(line)
		for len(runes) > maxWidth {
			result = append(result, string(runes[:maxWidth]))
			runes = runes[maxWidth:]
		}
		result = append(result, string(runes))
	}
	return result
}

func (dp detailsPane) visibleRows() int {
	return max(1, dp.height-4)
}

func (dp *detailsPane) setSize(w, h int) {
	dp.width = w
	dp.height = h
}
