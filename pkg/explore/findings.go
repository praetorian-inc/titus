package explore

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/praetorian-inc/titus/pkg/types"
)

// sortField defines which column to sort by.
type sortField int

const (
	sortByRuleName sortField = iota
	sortByMatches
	sortByValidation
	sortByConfidence
	sortByStatus
	sortFieldCount // sentinel
)

var sortFieldNames = [sortFieldCount]string{
	"Rule Name", "Locations", "Validation", "Confidence", "Status",
}

// findingsPane is the top-right findings table.
type findingsPane struct {
	rows    []*findingRow // filtered rows
	allRows []*findingRow // all rows (unfiltered)
	cursor  int
	offset  int
	width   int
	height  int
	focused bool
	sortBy  sortField
	sortAsc bool
	// repoFilter is the Repository facet selection; the count column and its
	// sort count only locations visible under it.
	repoFilter map[string]bool
	// counts caches locationCount per finding under repoFilter. It is a new
	// map whenever the filter changes, never cleared in place, so copies of
	// the pane with different filters keep their own counts. A row change
	// keeps it: a finding's count depends only on its own locations and the
	// filter, and both are fixed after load.
	counts map[*findingRow]int

	// Column widths
	colRuleName   int
	colGroups     int
	colMatches    int
	colValidation int
	colConfidence int
	colStatus     int
}

func newFindingsPane(rows []*findingRow) findingsPane {
	fp := findingsPane{
		allRows: rows,
		rows:    rows,
		sortAsc: true,
		counts:  make(map[*findingRow]int),
	}
	fp.sort()
	return fp
}

// setRepoFilter sets the Repository facet selection that the count column
// counts under. Call it before setFilteredRows when the selection changes.
// Callers pass a fresh map and never modify it afterwards.
func (fp *findingsPane) setRepoFilter(sel map[string]bool) {
	fp.repoFilter = sel
	fp.counts = make(map[*findingRow]int)
}

// locationCount is the number of the finding's locations visible under the
// repo filter, summed over its matches. It is the count cell and its sort key.
// Locations do not change after load, so each count is computed once per
// filter and then read from fp.counts.
func (fp findingsPane) locationCount(f *findingRow) int {
	if n, ok := fp.counts[f]; ok {
		return n
	}
	n := 0
	for _, mr := range f.Matches {
		n += len(visibleOccurrences(mr.Occurrences, fp.repoFilter))
	}
	if fp.counts != nil {
		fp.counts[f] = n
	}
	return n
}

// setFilteredRows replaces the shown rows and re-sorts them, because the
// location count, and so the order, depends on the current repo filter. The
// cursor follows the selected finding when it is still shown.
func (fp *findingsPane) setFilteredRows(rows []*findingRow) {
	sel := fp.selectedFinding()
	fp.rows = rows
	fp.sort()
	fp.restoreCursor(sel)
}

// restoreCursor puts the cursor on sel if it is among the rows, otherwise
// clamps it into range.
func (fp *findingsPane) restoreCursor(sel *findingRow) {
	if i := slices.Index(fp.rows, sel); sel != nil && i >= 0 {
		fp.cursor = i
	} else if fp.cursor >= len(fp.rows) {
		fp.cursor = max(0, len(fp.rows)-1)
	}
	fp.ensureVisible()
}

func (fp findingsPane) selectedFinding() *findingRow {
	if fp.cursor < 0 || fp.cursor >= len(fp.rows) {
		return nil
	}
	return fp.rows[fp.cursor]
}

func (fp findingsPane) Update(msg tea.Msg) (findingsPane, tea.Cmd) {
	if !fp.focused {
		return fp, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case keyMatches(msg, defaultKeys.Up):
			if fp.cursor > 0 {
				fp.cursor--
				fp.ensureVisible()
			}
		case keyMatches(msg, defaultKeys.Down):
			if fp.cursor < len(fp.rows)-1 {
				fp.cursor++
				fp.ensureVisible()
			}
		case keyMatches(msg, defaultKeys.Home):
			fp.cursor = 0
			fp.offset = 0
		case keyMatches(msg, defaultKeys.End):
			fp.cursor = max(0, len(fp.rows)-1)
			fp.ensureVisible()
		case keyMatches(msg, defaultKeys.PageDown):
			fp.cursor = min(fp.cursor+fp.visibleRows(), len(fp.rows)-1)
			fp.ensureVisible()
		case keyMatches(msg, defaultKeys.PageUp):
			fp.cursor = max(fp.cursor-fp.visibleRows(), 0)
			fp.ensureVisible()
		case keyMatches(msg, defaultKeys.SortNext):
			sel := fp.selectedFinding()
			fp.sortBy = (fp.sortBy + 1) % sortFieldCount
			fp.sort()
			fp.restoreCursor(sel)
		}
	}

	return fp, nil
}

// sort orders the rows by the current field and direction. It is stable, so
// rows with equal keys keep their relative order.
func (fp *findingsPane) sort() {
	var compare func(a, b *findingRow) int
	switch fp.sortBy {
	case sortByRuleName:
		compare = func(a, b *findingRow) int { return cmp.Compare(a.RuleName, b.RuleName) }
	case sortByMatches:
		// locationCount is cached per filter, so the comparator stays cheap.
		compare = func(a, b *findingRow) int { return cmp.Compare(fp.locationCount(a), fp.locationCount(b)) }
	case sortByValidation:
		compare = func(a, b *findingRow) int { return cmp.Compare(a.ValidationStatus, b.ValidationStatus) }
	case sortByConfidence:
		compare = func(a, b *findingRow) int { return cmp.Compare(a.Confidence, b.Confidence) }
	case sortByStatus:
		compare = func(a, b *findingRow) int { return cmp.Compare(a.AnnotationStatus, b.AnnotationStatus) }
	default:
		return
	}
	if !fp.sortAsc {
		asc := compare
		compare = func(a, b *findingRow) int { return asc(b, a) }
	}
	slices.SortStableFunc(fp.rows, compare)
}

func (fp findingsPane) View() string {
	if fp.width <= 0 || fp.height <= 0 {
		return ""
	}

	// Calculate column widths
	contentWidth := max(0, fp.width-4) // borders; never negative in a tiny terminal
	fp.colMatches = 8
	fp.colValidation = 8
	fp.colConfidence = 8
	fp.colStatus = 8
	fp.colGroups = min(30, contentWidth/4)
	fp.colRuleName = contentWidth - fp.colGroups - fp.colMatches - fp.colValidation - fp.colConfidence - fp.colStatus - 5 // separators
	if fp.colRuleName < 10 {
		fp.colRuleName = 10
	}

	var b strings.Builder

	// Header row
	sortIndicator := func(f sortField) string {
		if fp.sortBy == f {
			if fp.sortAsc {
				return " ^"
			}
			return " v"
		}
		return ""
	}

	header := fmt.Sprintf(" %s %s %*s %s %*s %s",
		cell("Rule Name"+sortIndicator(sortByRuleName), fp.colRuleName),
		cell("Groups", fp.colGroups),
		fp.colMatches, "Locs"+sortIndicator(sortByMatches),
		cell("Valid"+sortIndicator(sortByValidation), fp.colValidation),
		fp.colConfidence, "Conf"+sortIndicator(sortByConfidence),
		cell("Status"+sortIndicator(sortByStatus), fp.colStatus),
	)
	b.WriteString(headerRowStyle.Width(contentWidth).Render(truncateString(header, contentWidth)))
	b.WriteString("\n")

	// Separator
	b.WriteString(strings.Repeat("─", contentWidth))
	b.WriteString("\n")

	// Data rows
	visibleEnd := min(fp.offset+fp.visibleRows(), len(fp.rows))
	for i := fp.offset; i < visibleEnd; i++ {
		row := fp.rows[i]
		isCurrent := i == fp.cursor

		groupStr := truncateString(formatGroups(row.Groups), fp.colGroups)
		valStr := renderValidationStatus(row.ValidationStatus)
		confStr := ""
		if row.Confidence > 0 {
			confStr = fmt.Sprintf("%.2f", row.Confidence)
		}
		statusStr := renderAnnotationStatus(row.AnnotationStatus)

		line := fmt.Sprintf(" %s %s %*d %s %*s %s",
			cell(types.SanitizeDisplay(row.RuleName), fp.colRuleName),
			cell(groupStr, fp.colGroups),
			fp.colMatches, fp.locationCount(row),
			cell(valStr, fp.colValidation),
			fp.colConfidence, confStr,
			cell(statusStr, fp.colStatus),
		)

		if isCurrent && fp.focused {
			line = selectedRowStyle.Width(contentWidth).Render(stripAnsi(line))
		}

		b.WriteString(padRight(line, contentWidth))
		if i < visibleEnd-1 {
			b.WriteString("\n")
		}
	}

	// Fill empty rows
	for i := visibleEnd - fp.offset; i < fp.visibleRows(); i++ {
		b.WriteString(strings.Repeat(" ", contentWidth))
		if i < fp.visibleRows()-1 {
			b.WriteString("\n")
		}
	}

	title := titleStyle.Render(fmt.Sprintf(" Findings (%d/%d) [sort: %s] ", len(fp.rows), len(fp.allRows), sortFieldNames[fp.sortBy]))

	borderStyle := inactiveBorderStyle
	if fp.focused {
		borderStyle = activeBorderStyle
	}

	content := borderStyle.
		Width(fp.width - 2).
		Height(fp.height - 3).
		Render(b.String())

	return lipgloss.JoinVertical(lipgloss.Left, title, content)
}

func (fp findingsPane) visibleRows() int {
	return max(1, fp.height-6) // title + border + header + separator
}

func (fp *findingsPane) ensureVisible() {
	if fp.cursor < fp.offset {
		fp.offset = fp.cursor
	}
	if fp.cursor >= fp.offset+fp.visibleRows() {
		fp.offset = fp.cursor - fp.visibleRows() + 1
	}
}

func (fp *findingsPane) setSize(w, h int) {
	fp.width = w
	fp.height = h
}

// formatGroups renders capture groups as a display string.
func formatGroups(groups [][]byte) string {
	if len(groups) == 0 {
		return ""
	}
	parts := make([]string, len(groups))
	for i, g := range groups {
		parts[i] = sanitizeForDisplay(g)
	}
	return strings.Join(parts, ", ")
}

// cell fits s to a column of width terminal cells: truncated when wider, padded
// when narrower. It measures display width, so wide or styled text keeps the
// columns after it aligned, where a %-*s verb would pad by bytes.
func cell(s string, width int) string {
	return padRight(truncateString(s, width), width)
}
