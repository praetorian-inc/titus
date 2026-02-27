package explore

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// filterPane is the left-side faceted search tree.
type filterPane struct {
	facets  *facetState
	cursor  int          // flat index across all facet items
	items   []filterItem // flattened tree items
	width   int
	height  int
	offset  int // scroll offset
	focused bool
}

type filterItemKind int

const (
	filterItemCategory filterItemKind = iota
	filterItemValue
)

type filterItem struct {
	Kind     filterItemKind
	Label    string
	FacetID  facetID
	ValueIdx int // index into facets.Values[FacetID]
	Expanded bool
}

func newFilterPane(facets *facetState) filterPane {
	fp := filterPane{
		facets: facets,
	}
	fp.rebuildItems()
	return fp
}

// rebuildItems flattens the facet tree into a list of items.
func (fp *filterPane) rebuildItems() {
	fp.items = nil
	for _, def := range facetDefs {
		values := fp.facets.Values[def.ID]
		if len(values) == 0 {
			continue
		}
		fp.items = append(fp.items, filterItem{
			Kind:     filterItemCategory,
			Label:    def.Label,
			FacetID:  def.ID,
			Expanded: true,
		})
		// Find the category item we just added to check expanded
		catIdx := len(fp.items) - 1
		if fp.items[catIdx].Expanded {
			for i, v := range values {
				fp.items = append(fp.items, filterItem{
					Kind:     filterItemValue,
					Label:    v.Value,
					FacetID:  def.ID,
					ValueIdx: i,
				})
			}
		}
	}
}

func (fp filterPane) Update(msg tea.Msg) (filterPane, tea.Cmd) {
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
			if fp.cursor < len(fp.items)-1 {
				fp.cursor++
				fp.ensureVisible()
			}
		case keyMatches(msg, defaultKeys.Home):
			fp.cursor = 0
			fp.offset = 0
		case keyMatches(msg, defaultKeys.End):
			fp.cursor = max(0, len(fp.items)-1)
			fp.ensureVisible()
		case keyMatches(msg, defaultKeys.PageDown):
			fp.cursor = min(fp.cursor+fp.visibleRows(), len(fp.items)-1)
			fp.ensureVisible()
		case keyMatches(msg, defaultKeys.PageUp):
			fp.cursor = max(fp.cursor-fp.visibleRows(), 0)
			fp.ensureVisible()
		case keyMatches(msg, defaultKeys.ToggleFilter):
			fp.toggleCurrent()
		case keyMatches(msg, defaultKeys.ResetFilter):
			fp.facets.resetAll()
		}
	}

	return fp, nil
}

func (fp *filterPane) toggleCurrent() {
	if fp.cursor < 0 || fp.cursor >= len(fp.items) {
		return
	}
	item := &fp.items[fp.cursor]
	switch item.Kind {
	case filterItemCategory:
		item.Expanded = !item.Expanded
		fp.rebuildItems()
		// Keep cursor on category
		for i, it := range fp.items {
			if it.Kind == filterItemCategory && it.FacetID == item.FacetID {
				fp.cursor = i
				break
			}
		}
	case filterItemValue:
		values := fp.facets.Values[item.FacetID]
		if item.ValueIdx < len(values) {
			values[item.ValueIdx].Selected = !values[item.ValueIdx].Selected
		}
	}
}

func (fp filterPane) View() string {
	if fp.width <= 0 || fp.height <= 0 {
		return ""
	}

	var b strings.Builder
	visibleEnd := min(fp.offset+fp.visibleRows(), len(fp.items))

	for i := fp.offset; i < visibleEnd; i++ {
		item := fp.items[i]
		isCurrent := i == fp.cursor

		var line string
		switch item.Kind {
		case filterItemCategory:
			arrow := "▸"
			if item.Expanded {
				arrow = "▾"
			}
			line = facetLabelStyle.Render(fmt.Sprintf(" %s %s", arrow, item.Label))
		case filterItemValue:
			values := fp.facets.Values[item.FacetID]
			var marker string
			count := 0
			if item.ValueIdx < len(values) {
				v := values[item.ValueIdx]
				count = v.Count
				if v.Selected {
					marker = "+"
				} else {
					marker = " "
				}
			}
			label := truncateString(item.Label, fp.width-12)
			countStr := facetCountStyle.Render(fmt.Sprintf("(%d)", count))
			if marker == "+" {
				line = fmt.Sprintf("   %s %s %s", facetSelectedStyle.Render(marker), facetSelectedStyle.Render(label), countStr)
			} else {
				line = fmt.Sprintf("   %s %s %s", marker, label, countStr)
			}
		}

		if isCurrent && fp.focused {
			line = selectedRowStyle.Width(fp.width - 2).Render(stripAnsi(line))
		}

		// Pad to width
		line = padRight(line, fp.width-2)
		b.WriteString(line)
		if i < visibleEnd-1 {
			b.WriteString("\n")
		}
	}

	// Fill remaining lines
	for i := visibleEnd - fp.offset; i < fp.visibleRows(); i++ {
		b.WriteString(strings.Repeat(" ", fp.width-2))
		if i < fp.visibleRows()-1 {
			b.WriteString("\n")
		}
	}

	title := titleStyle.Render(" Filters ")

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

func (fp filterPane) visibleRows() int {
	return max(1, fp.height-4) // account for title + border
}

func (fp *filterPane) ensureVisible() {
	if fp.cursor < fp.offset {
		fp.offset = fp.cursor
	}
	if fp.cursor >= fp.offset+fp.visibleRows() {
		fp.offset = fp.cursor - fp.visibleRows() + 1
	}
}

func (fp *filterPane) setSize(w, h int) {
	fp.width = w
	fp.height = h
}

// Helper functions

func keyMatches(msg tea.KeyMsg, binding key.Binding) bool {
	for _, k := range binding.Keys() {
		if msg.String() == k {
			return true
		}
	}
	return false
}

func truncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func padRight(s string, width int) string {
	visLen := lipgloss.Width(s)
	if visLen >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visLen)
}

// stripAnsi removes ANSI escape sequences for re-styling.
func stripAnsi(s string) string {
	var result strings.Builder
	inEscape := false
	for _, r := range s {
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
			}
			continue
		}
		result.WriteRune(r)
	}
	return result.String()
}
