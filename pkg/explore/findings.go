package explore

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	"Rule Name", "Matches", "Validation", "Confidence", "Status",
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
	}
	fp.sort()
	return fp
}

func (fp *findingsPane) setFilteredRows(rows []*findingRow) {
	fp.rows = rows
	if fp.cursor >= len(fp.rows) {
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
			fp.sortBy = (fp.sortBy + 1) % sortFieldCount
			fp.sort()
		}
	}

	return fp, nil
}

func (fp *findingsPane) sort() {
	switch fp.sortBy {
	case sortByRuleName:
		sortSlice(fp.rows, func(a, b *findingRow) bool { return a.RuleName < b.RuleName }, fp.sortAsc)
	case sortByMatches:
		sortSlice(fp.rows, func(a, b *findingRow) bool { return a.MatchCount < b.MatchCount }, fp.sortAsc)
	case sortByValidation:
		sortSlice(fp.rows, func(a, b *findingRow) bool { return a.ValidationStatus < b.ValidationStatus }, fp.sortAsc)
	case sortByConfidence:
		sortSlice(fp.rows, func(a, b *findingRow) bool { return a.Confidence < b.Confidence }, fp.sortAsc)
	case sortByStatus:
		sortSlice(fp.rows, func(a, b *findingRow) bool { return a.AnnotationStatus < b.AnnotationStatus }, fp.sortAsc)
	}
}

func sortSlice[T any](s []T, less func(a, b T) bool, asc bool) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0; j-- {
			if asc {
				if less(s[j], s[j-1]) {
					s[j], s[j-1] = s[j-1], s[j]
				}
			} else {
				if less(s[j-1], s[j]) {
					s[j], s[j-1] = s[j-1], s[j]
				}
			}
		}
	}
}

func (fp findingsPane) View() string {
	if fp.width <= 0 || fp.height <= 0 {
		return ""
	}

	// Calculate column widths
	contentWidth := fp.width - 4 // borders
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

	header := fmt.Sprintf(" %-*s %-*s %*s %-*s %*s %-*s",
		fp.colRuleName, "Rule Name"+sortIndicator(sortByRuleName),
		fp.colGroups, "Groups",
		fp.colMatches, "Matches"+sortIndicator(sortByMatches),
		fp.colValidation, "Valid"+sortIndicator(sortByValidation),
		fp.colConfidence, "Conf"+sortIndicator(sortByConfidence),
		fp.colStatus, "Status"+sortIndicator(sortByStatus),
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

		line := fmt.Sprintf(" %-*s %-*s %*d %-*s %*s %-*s",
			fp.colRuleName, truncateString(row.RuleName, fp.colRuleName),
			fp.colGroups, groupStr,
			fp.colMatches, row.MatchCount,
			fp.colValidation, valStr,
			fp.colConfidence, confStr,
			fp.colStatus, statusStr,
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
		parts[i] = string(g)
	}
	return strings.Join(parts, ", ")
}
