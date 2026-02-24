package explore

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/praetorian-inc/titus/pkg/types"
)

// focusedPane tracks which pane has keyboard focus.
type focusedPane int

const (
	paneFilters focusedPane = iota
	paneFindings
	paneDetails
)

// overlay tracks which modal overlay is active.
type overlay int

const (
	overlayNone overlay = iota
	overlayHelp
	overlaySource
	overlayComment
)

// pagerFinishedMsg is sent when an external pager process exits.
type pagerFinishedMsg struct{ err error }

// Model is the root Bubble Tea model for the explore TUI.
type Model struct {
	data     *exploreData
	filters  filterPane
	findings findingsPane
	details  detailsPane

	focus         focusedPane
	activeOverlay overlay
	showFilters   bool

	// Help state
	helpContent string
	helpOffset  int

	// Source viewer state
	sourceContent string
	sourceOffset  int

	// Comment input state
	commentInput  string
	commentTarget string // "finding" or "match"
	commentID     string

	width  int
	height int
	err    error
}

// New creates a new Model by loading data from the given datastore path.
func New(datastorePath string) (Model, error) {
	data, err := loadData(datastorePath)
	if err != nil {
		return Model{}, err
	}

	facets := buildFacets(data.findings)

	m := Model{
		data:        data,
		filters:     newFilterPane(facets),
		findings:    newFindingsPane(data.findings),
		details:     newDetailsPane(),
		focus:       paneFindings,
		showFilters: true,
	}

	// Set initial focus
	m.findings.focused = true

	// Select first finding
	if f := m.findings.selectedFinding(); f != nil {
		m.details.setFinding(f)
	}

	return m, nil
}

func (m Model) Init() tea.Cmd {
	return tea.SetWindowTitle("titus explore")
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()
		return m, nil

	case pagerFinishedMsg:
		// Pager exited, TUI resumes automatically
		return m, nil

	case tea.MouseMsg:
		if m.activeOverlay != overlayNone {
			return m, nil
		}
		if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft {
			return m, nil
		}
		m.handleMouseClick(msg.X, msg.Y)
		return m, nil

	case tea.KeyMsg:
		// Handle overlays first
		if m.activeOverlay != overlayNone {
			return m.updateOverlay(msg)
		}

		// Global keys (work regardless of focus)
		switch {
		case keyMatches(msg, defaultKeys.ForceQuit):
			return m, tea.Quit
		case keyMatches(msg, defaultKeys.Quit):
			return m, tea.Quit
		case keyMatches(msg, defaultKeys.ToggleHelp):
			m.activeOverlay = overlayHelp
			m.helpOffset = 0
			m.helpContent = renderHelp()
			return m, nil
		case keyMatches(msg, defaultKeys.ToggleFilters):
			m.showFilters = !m.showFilters
			m.updateLayout()
			return m, nil
		case keyMatches(msg, defaultKeys.FocusFilters):
			m.setFocus(paneFilters)
			return m, nil
		case keyMatches(msg, defaultKeys.FocusFindings):
			m.setFocus(paneFindings)
			return m, nil
		case keyMatches(msg, defaultKeys.FocusDetails):
			m.setFocus(paneDetails)
			return m, nil
		}

		// Annotation keys (findings or details)
		if m.focus == paneFindings || m.focus == paneDetails {
			switch {
			case keyMatches(msg, defaultKeys.Accept):
				m.setAnnotation("accept")
				return m, nil
			case keyMatches(msg, defaultKeys.Reject):
				m.setAnnotation("reject")
				return m, nil
			case keyMatches(msg, defaultKeys.AcceptNext):
				m.setAnnotation("accept")
				m.moveNext()
				return m, nil
			case keyMatches(msg, defaultKeys.RejectNext):
				m.setAnnotation("reject")
				m.moveNext()
				return m, nil
			case keyMatches(msg, defaultKeys.Comment):
				m.startComment()
				return m, nil
			case keyMatches(msg, defaultKeys.OpenSource):
				cmd := m.openSource()
				return m, cmd
			}
		}

		// Delegate to focused pane
		switch m.focus {
		case paneFilters:
			var cmd tea.Cmd
			m.filters, cmd = m.filters.Update(msg)
			m.applyFilters()
			return m, cmd
		case paneFindings:
			prevCursor := m.findings.cursor
			var cmd tea.Cmd
			m.findings, cmd = m.findings.Update(msg)
			if m.findings.cursor != prevCursor {
				if f := m.findings.selectedFinding(); f != nil {
					m.details.setFinding(f)
				}
			}
			return m, cmd
		case paneDetails:
			var cmd tea.Cmd
			m.details, cmd = m.details.Update(msg)
			return m, cmd
		}
	}

	return m, nil
}

func (m *Model) updateOverlay(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.activeOverlay {
	case overlayHelp:
		switch {
		case keyMatches(msg, defaultKeys.Quit),
			keyMatches(msg, defaultKeys.ForceQuit),
			keyMatches(msg, defaultKeys.ToggleHelp):
			m.activeOverlay = overlayNone
		case keyMatches(msg, defaultKeys.Down):
			m.helpOffset++
		case keyMatches(msg, defaultKeys.Up):
			if m.helpOffset > 0 {
				m.helpOffset--
			}
		case keyMatches(msg, defaultKeys.PageDown):
			m.helpOffset += m.height / 2
		case keyMatches(msg, defaultKeys.PageUp):
			m.helpOffset = max(0, m.helpOffset-m.height/2)
		}
	case overlaySource:
		switch {
		case keyMatches(msg, defaultKeys.Quit),
			keyMatches(msg, defaultKeys.ForceQuit),
			keyMatches(msg, defaultKeys.OpenSource):
			m.activeOverlay = overlayNone
		case keyMatches(msg, defaultKeys.Down):
			m.sourceOffset++
		case keyMatches(msg, defaultKeys.Up):
			if m.sourceOffset > 0 {
				m.sourceOffset--
			}
		case keyMatches(msg, defaultKeys.PageDown):
			m.sourceOffset += m.height / 2
		case keyMatches(msg, defaultKeys.PageUp):
			m.sourceOffset = max(0, m.sourceOffset-m.height/2)
		}
	case overlayComment:
		switch msg.String() {
		case "enter":
			m.saveComment()
			m.activeOverlay = overlayNone
		case "esc", "ctrl+c":
			m.activeOverlay = overlayNone
		case "backspace":
			if len(m.commentInput) > 0 {
				m.commentInput = m.commentInput[:len(m.commentInput)-1]
			}
		default:
			if len(msg.String()) == 1 || msg.String() == " " {
				m.commentInput += msg.String()
			}
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	// Render overlays
	if m.activeOverlay != overlayNone {
		return m.renderOverlay()
	}

	// Status bar (bottom)
	statusBar := m.renderStatusBar()

	// Main layout
	contentHeight := m.height - 2 // status bar + padding

	var mainContent string
	if m.showFilters {
		filtersWidth := min(m.width*30/100, 50)
		dataWidth := m.width - filtersWidth

		findingsHeight := contentHeight * 40 / 100
		detailsHeight := contentHeight - findingsHeight

		m.filters.setSize(filtersWidth, contentHeight)
		m.findings.setSize(dataWidth, findingsHeight)
		m.details.setSize(dataWidth, detailsHeight)

		filtersView := m.filters.View()
		findingsView := m.findings.View()
		detailsView := m.details.View()

		dataColumn := lipgloss.JoinVertical(lipgloss.Left, findingsView, detailsView)
		mainContent = lipgloss.JoinHorizontal(lipgloss.Top, filtersView, dataColumn)
	} else {
		dataWidth := m.width
		findingsHeight := contentHeight * 40 / 100
		detailsHeight := contentHeight - findingsHeight

		m.findings.setSize(dataWidth, findingsHeight)
		m.details.setSize(dataWidth, detailsHeight)

		findingsView := m.findings.View()
		detailsView := m.details.View()
		mainContent = lipgloss.JoinVertical(lipgloss.Left, findingsView, detailsView)
	}

	return lipgloss.JoinVertical(lipgloss.Left, mainContent, statusBar)
}

func (m *Model) renderStatusBar() string {
	left := statusBarStyle.Render(fmt.Sprintf(" %d findings | %d filtered",
		len(m.data.findings), len(m.findings.rows)))

	right := fmt.Sprintf("%s:%s  %s:%s  %s:%s  %s:%s  %s:%s  %s:%s  %s:%s  %s:%s",
		helpKeyStyle.Render("j/k"), helpDescStyle.Render("nav"),
		helpKeyStyle.Render("f/d"), helpDescStyle.Render("focus"),
		helpKeyStyle.Render("a/r"), helpDescStyle.Render("accept/reject"),
		helpKeyStyle.Render("c"), helpDescStyle.Render("comment"),
		helpKeyStyle.Render("s"), helpDescStyle.Render("sort"),
		helpKeyStyle.Render("o"), helpDescStyle.Render("source"),
		helpKeyStyle.Render("F7"), helpDescStyle.Render("filters"),
		helpKeyStyle.Render("?"), helpDescStyle.Render("help"),
	)

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 0 {
		gap = 0
	}

	return left + strings.Repeat(" ", gap) + right
}

func (m *Model) renderOverlay() string {
	overlayWidth := m.width * 80 / 100
	overlayHeight := m.height * 80 / 100

	var content string
	var title string

	switch m.activeOverlay {
	case overlayHelp:
		title = " Help (q to close) "
		content = m.renderHelpContent(overlayWidth-6, overlayHeight-4)
	case overlaySource:
		title = " Source (q to close) "
		content = m.renderSourceContent(overlayWidth-6, overlayHeight-4)
	case overlayComment:
		title = " Comment (enter to save, esc to cancel) "
		overlayWidth = min(60, m.width-4)
		overlayHeight = 5
		content = fmt.Sprintf("\n  > %s_\n", m.commentInput)
	}

	box := modalStyle.
		Width(overlayWidth - 4).
		Height(overlayHeight - 2).
		Render(content)

	titleRendered := titleStyle.Render(title)

	overlayView := lipgloss.JoinVertical(lipgloss.Left, titleRendered, box)

	// Center on screen
	hPad := (m.width - lipgloss.Width(overlayView)) / 2
	vPad := (m.height - lipgloss.Height(overlayView)) / 2

	return strings.Repeat("\n", max(0, vPad)) +
		lipgloss.NewStyle().PaddingLeft(max(0, hPad)).Render(overlayView)
}

func (m *Model) renderHelpContent(width, height int) string {
	lines := strings.Split(m.helpContent, "\n")
	if m.helpOffset >= len(lines) {
		m.helpOffset = max(0, len(lines)-1)
	}
	end := min(m.helpOffset+height, len(lines))
	visible := lines[m.helpOffset:end]
	return strings.Join(visible, "\n")
}

func (m *Model) renderSourceContent(width, height int) string {
	if m.sourceContent == "" {
		return "  No source available"
	}
	lines := strings.Split(m.sourceContent, "\n")
	if m.sourceOffset >= len(lines) {
		m.sourceOffset = max(0, len(lines)-1)
	}
	end := min(m.sourceOffset+height, len(lines))
	visible := lines[m.sourceOffset:end]
	return strings.Join(visible, "\n")
}

func (m *Model) setFocus(p focusedPane) {
	m.filters.focused = p == paneFilters
	m.findings.focused = p == paneFindings
	m.details.focused = p == paneDetails
	m.focus = p
}

func (m *Model) handleMouseClick(x, y int) {
	contentHeight := m.height - 2

	if m.showFilters {
		filtersWidth := min(m.width*30/100, 50)
		findingsHeight := contentHeight * 40 / 100

		if x < filtersWidth && y < contentHeight {
			// Clicked in filters pane
			m.setFocus(paneFilters)
			row := y - 2 // title + border top
			if row >= 0 {
				idx := row + m.filters.offset
				if idx >= 0 && idx < len(m.filters.items) {
					m.filters.cursor = idx
					m.filters.toggleCurrent()
					m.applyFilters()
				}
			}
		} else if x >= filtersWidth && y < findingsHeight {
			// Clicked in findings pane
			m.setFocus(paneFindings)
			row := y - 4 // title + border top + header + separator
			if row >= 0 {
				idx := row + m.findings.offset
				if idx >= 0 && idx < len(m.findings.rows) {
					m.findings.cursor = idx
					if f := m.findings.selectedFinding(); f != nil {
						m.details.setFinding(f)
					}
				}
			}
		} else if x >= filtersWidth && y >= findingsHeight {
			// Clicked in details pane
			m.setFocus(paneDetails)
		}
	} else {
		findingsHeight := contentHeight * 40 / 100

		if y < findingsHeight {
			// Clicked in findings pane
			m.setFocus(paneFindings)
			row := y - 4
			if row >= 0 {
				idx := row + m.findings.offset
				if idx >= 0 && idx < len(m.findings.rows) {
					m.findings.cursor = idx
					if f := m.findings.selectedFinding(); f != nil {
						m.details.setFinding(f)
					}
				}
			}
		} else {
			// Clicked in details pane
			m.setFocus(paneDetails)
		}
	}
}

func (m *Model) applyFilters() {
	if !m.filters.facets.hasActiveFilters() {
		m.findings.setFilteredRows(m.data.findings)
	} else {
		var filtered []*findingRow
		for _, f := range m.data.findings {
			if m.filters.facets.matchesFinding(f) {
				filtered = append(filtered, f)
			}
		}
		m.findings.setFilteredRows(filtered)
	}
	// Update facet counts based on all findings (not just filtered)
	m.filters.facets.updateCounts(m.data.findings)

	// Update details
	if f := m.findings.selectedFinding(); f != nil {
		m.details.setFinding(f)
	} else {
		m.details.setFinding(nil)
	}
}

func (m *Model) setAnnotation(status string) {
	if m.focus == paneFindings {
		f := m.findings.selectedFinding()
		if f == nil {
			return
		}
		// Toggle: if same status, clear it
		if f.AnnotationStatus == status {
			f.AnnotationStatus = ""
			_ = m.data.setFindingAnnotation(f.FindingID, "", f.Comment)
		} else {
			f.AnnotationStatus = status
			_ = m.data.setFindingAnnotation(f.FindingID, status, f.Comment)
		}
	} else if m.focus == paneDetails {
		match := m.details.selectedMatch()
		if match == nil {
			return
		}
		if match.AnnotationStatus == status {
			match.AnnotationStatus = ""
			_ = m.data.setMatchAnnotation(match.StructuralID, "", match.Comment)
		} else {
			match.AnnotationStatus = status
			_ = m.data.setMatchAnnotation(match.StructuralID, status, match.Comment)
		}
	}
}

func (m *Model) moveNext() {
	if m.focus == paneFindings {
		if m.findings.cursor < len(m.findings.rows)-1 {
			m.findings.cursor++
			m.findings.ensureVisible()
			if f := m.findings.selectedFinding(); f != nil {
				m.details.setFinding(f)
			}
		}
	} else if m.focus == paneDetails {
		if m.finding() != nil && m.details.matchCursor < len(m.finding().Matches)-1 {
			m.details.matchCursor++
		}
	}
}

func (m *Model) finding() *findingRow {
	return m.findings.selectedFinding()
}

func (m *Model) startComment() {
	if m.focus == paneFindings {
		f := m.findings.selectedFinding()
		if f == nil {
			return
		}
		m.commentTarget = "finding"
		m.commentID = f.FindingID
		m.commentInput = f.Comment
	} else if m.focus == paneDetails {
		match := m.details.selectedMatch()
		if match == nil {
			return
		}
		m.commentTarget = "match"
		m.commentID = match.StructuralID
		m.commentInput = match.Comment
	}
	m.activeOverlay = overlayComment
}

func (m *Model) saveComment() {
	if m.commentTarget == "finding" {
		f := m.findings.selectedFinding()
		if f != nil {
			f.Comment = m.commentInput
			_ = m.data.setFindingAnnotation(f.FindingID, f.AnnotationStatus, f.Comment)
		}
	} else if m.commentTarget == "match" {
		match := m.details.selectedMatch()
		if match != nil {
			match.Comment = m.commentInput
			_ = m.data.setMatchAnnotation(match.StructuralID, match.AnnotationStatus, match.Comment)
		}
	}
}

func (m *Model) openSource() tea.Cmd {
	match := m.details.selectedMatch()
	if match == nil {
		return nil
	}

	// Check if match has FileProvenance with a file that exists on disk
	for _, prov := range match.Provenance {
		if fp, ok := prov.(types.FileProvenance); ok {
			if _, err := os.Stat(fp.FilePath); err == nil {
				return m.openInPager(fp.FilePath, match.Location.Source.Start.Line)
			}
		}
	}

	// Fallback: show snippet in overlay
	var sb strings.Builder
	if len(match.Snippet.Before) > 0 {
		sb.Write(match.Snippet.Before)
	}
	sb.Write(match.Snippet.Matching)
	if len(match.Snippet.After) > 0 {
		sb.Write(match.Snippet.After)
	}

	m.sourceContent = sb.String()
	m.sourceOffset = 0
	m.activeOverlay = overlaySource
	return nil
}

func (m *Model) openInPager(filePath string, line int) tea.Cmd {
	pager := os.Getenv("PAGER")
	if pager == "" {
		pager = "less"
	}

	var args []string
	if line > 0 && pager == "less" {
		args = append(args, fmt.Sprintf("+%d", line))
	}
	args = append(args, filePath)

	c := exec.Command(pager, args...)
	return tea.ExecProcess(c, func(err error) tea.Msg {
		return pagerFinishedMsg{err: err}
	})
}

func (m *Model) updateLayout() {
	// Layout recalculation happens in View() based on current dimensions
}

// Close releases resources held by the model.
func (m *Model) Close() error {
	if m.data != nil {
		return m.data.close()
	}
	return nil
}

// renderHelp generates help text.
func renderHelp() string {
	return `Titus Explore - Interactive Findings Browser

NAVIGATION
  j/k or Up/Down    Move cursor up/down
  h/l or Left/Right Navigate matches (details) or collapse/expand (filters)
  Ctrl+f/Ctrl+b     Page down/up
  g/G               Jump to top/bottom

FOCUS
  F1                Focus filters pane
  f                 Focus findings pane
  d                 Focus details pane
  F7                Toggle filters pane visibility

FILTERS
  x or Space        Toggle filter value
  Ctrl+r            Reset all filters

ANNOTATIONS
  a                 Toggle accept on finding/match
  r                 Toggle reject on finding/match
  A                 Accept and move to next
  R                 Reject and move to next
  c                 Add/edit comment

VIEWS
  s                 Cycle sort column
  o                 Open source (pager for files, overlay for git)
  ?                 Toggle this help screen

QUIT
  q                 Quit
  Ctrl+c            Force quit
`
}
