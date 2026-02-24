package explore

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/praetorian-inc/titus/pkg/types"
)

// detailsPane shows match details for the selected finding.
type detailsPane struct {
	finding     *findingRow
	matchCursor int
	width       int
	height      int
	offset      int // scroll offset for content
	focused     bool
}

func newDetailsPane() detailsPane {
	return detailsPane{}
}

func (dp *detailsPane) setFinding(f *findingRow) {
	dp.finding = f
	dp.matchCursor = 0
	dp.offset = 0
}

func (dp detailsPane) selectedMatch() *matchRow {
	if dp.finding == nil || dp.matchCursor < 0 || dp.matchCursor >= len(dp.finding.Matches) {
		return nil
	}
	return dp.finding.Matches[dp.matchCursor]
}

func (dp detailsPane) Update(msg tea.Msg) (detailsPane, tea.Cmd) {
	if !dp.focused {
		return dp, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case keyMatches(msg, defaultKeys.Up):
			if dp.offset > 0 {
				dp.offset--
			}
		case keyMatches(msg, defaultKeys.Down):
			dp.offset++
		case keyMatches(msg, defaultKeys.Left):
			if dp.matchCursor > 0 {
				dp.matchCursor--
				dp.offset = 0
			}
		case keyMatches(msg, defaultKeys.Right):
			if dp.finding != nil && dp.matchCursor < len(dp.finding.Matches)-1 {
				dp.matchCursor++
				dp.offset = 0
			}
		case keyMatches(msg, defaultKeys.Home):
			dp.offset = 0
		case keyMatches(msg, defaultKeys.PageDown):
			dp.offset += dp.visibleRows()
		case keyMatches(msg, defaultKeys.PageUp):
			dp.offset = max(0, dp.offset-dp.visibleRows())
		}
	}

	return dp, nil
}

func (dp detailsPane) View() string {
	if dp.width <= 0 || dp.height <= 0 {
		return ""
	}

	contentWidth := dp.width - 4

	var lines []string

	if dp.finding == nil {
		lines = append(lines, "  No finding selected")
	} else {
		f := dp.finding

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
			lines = append(lines, fmt.Sprintf("  %s %s",
				fieldLabelStyle.Render(fmt.Sprintf("Group %d:", i+1)),
				snippetMatchStyle.Render(string(g))))
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
		if len(f.Matches) > 0 {
			lines = append(lines, fmt.Sprintf("  %s",
				headerRowStyle.Render(fmt.Sprintf("Match %d/%d (h/l to navigate)", dp.matchCursor+1, len(f.Matches)))))
			lines = append(lines, "  "+strings.Repeat("─", min(40, contentWidth-4)))

			m := dp.selectedMatch()
			if m != nil {
				lines = append(lines, renderMatchDetails(m, contentWidth)...)
			}
		} else {
			lines = append(lines, "  No matches")
		}
	}

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
		b.WriteString(padRight(truncateString(line, contentWidth), contentWidth))
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

func renderMatchDetails(m *matchRow, maxWidth int) []string {
	var lines []string

	// File/Provenance
	if len(m.Provenance) > 0 {
		for _, prov := range m.Provenance {
			switch p := prov.(type) {
			case types.FileProvenance:
				lines = append(lines, fmt.Sprintf("  %s %s",
					fieldLabelStyle.Render("File:"),
					fieldValueStyle.Render(p.FilePath)))
			case types.GitProvenance:
				lines = append(lines, fmt.Sprintf("  %s %s",
					fieldLabelStyle.Render("Repo:"),
					fieldValueStyle.Render(p.RepoPath)))
				lines = append(lines, fmt.Sprintf("  %s %s",
					fieldLabelStyle.Render("Path:"),
					fieldValueStyle.Render(p.BlobPath)))
				if p.Commit != nil {
					lines = append(lines, fmt.Sprintf("  %s %s",
						fieldLabelStyle.Render("Commit:"),
						fieldValueStyle.Render(p.Commit.CommitID)))
					if p.Commit.AuthorName != "" {
						lines = append(lines, fmt.Sprintf("  %s %s <%s>",
							fieldLabelStyle.Render("Author:"),
							fieldValueStyle.Render(p.Commit.AuthorName),
							p.Commit.AuthorEmail))
					}
				}
			}
		}
	}

	// Blob
	lines = append(lines, fmt.Sprintf("  %s %s",
		fieldLabelStyle.Render("Blob:"),
		fieldValueStyle.Render(m.BlobID.Hex()[:12]+"...")))

	// Location
	if m.Location.Source.Start.Line > 0 {
		lines = append(lines, fmt.Sprintf("  %s %d:%d - %d:%d (bytes %d-%d)",
			fieldLabelStyle.Render("Location:"),
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
			lines = append(lines, fmt.Sprintf("    %s: %s",
				fieldLabelStyle.Render(name),
				snippetMatchStyle.Render(truncateString(string(val), 60))))
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
	before := strings.TrimRight(string(m.Snippet.Before), "\n\r")
	matching := string(m.Snippet.Matching)
	after := strings.TrimLeft(string(m.Snippet.After), "\n\r")

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

func (dp detailsPane) visibleRows() int {
	return max(1, dp.height-4)
}

func (dp *detailsPane) setSize(w, h int) {
	dp.width = w
	dp.height = h
}
