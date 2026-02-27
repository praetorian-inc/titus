package explore

import "github.com/charmbracelet/lipgloss"

// Colors
var (
	colorPrimary   = lipgloss.Color("#e63948")  // red
	colorSecondary = lipgloss.Color("10")  // green
	colorMatch     = lipgloss.Color("#D4AF37")  // gold
	colorError     = lipgloss.Color("9")   // red
	colorMuted     = lipgloss.Color("8")   // gray
	colorValid     = lipgloss.Color("10")  // green
	colorInvalid   = lipgloss.Color("9")   // red
	colorUndeterm  = lipgloss.Color("#D4AF37")  // gold
	colorAccent    = lipgloss.Color("#11C3DB")  // cyan
	colorHighlight = lipgloss.Color("15")  // white
)

// Pane border styles
var (
	activeBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorPrimary)

	inactiveBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorMuted)
)

// Title style for pane headers
var titleStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(colorHighlight).
	Background(colorPrimary).
	Padding(0, 1)

// Table row styles
var (
	selectedRowStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("17")).
				Foreground(colorHighlight)

	normalRowStyle = lipgloss.NewStyle()

	headerRowStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent)
)

// Snippet styles
var (
	snippetMatchStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorMatch)

	snippetContextStyle = lipgloss.NewStyle().
				Foreground(colorMuted)
)

// Validation status styles
var (
	validStyle = lipgloss.NewStyle().
			Foreground(colorValid).
			Bold(true)

	invalidStyle = lipgloss.NewStyle().
			Foreground(colorInvalid).
			Bold(true)

	undeterminedStyle = lipgloss.NewStyle().
				Foreground(colorUndeterm)
)

// Status bar
var statusBarStyle = lipgloss.NewStyle().
	Foreground(colorMuted)

// Help styles
var (
	helpKeyStyle  = lipgloss.NewStyle().Foreground(colorAccent)
	helpDescStyle = lipgloss.NewStyle().Foreground(colorMuted)
)

// Facet styles
var (
	facetLabelStyle    = lipgloss.NewStyle().Bold(true).Foreground(colorPrimary)
	facetSelectedStyle = lipgloss.NewStyle().Foreground(colorSecondary)
	facetCountStyle    = lipgloss.NewStyle().Foreground(colorMuted)
)

// Annotation styles
var (
	acceptStyle = lipgloss.NewStyle().Foreground(colorValid).Bold(true)
	rejectStyle = lipgloss.NewStyle().Foreground(colorError).Bold(true)
)

// Detail field styles
var (
	fieldLabelStyle = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	fieldValueStyle = lipgloss.NewStyle().Foreground(colorHighlight)
)

// Modal overlay style
var modalStyle = lipgloss.NewStyle().
	Border(lipgloss.DoubleBorder()).
	BorderForeground(colorPrimary).
	Padding(1, 2)

// renderValidationStatus returns a styled string for a validation status.
func renderValidationStatus(status string) string {
	switch status {
	case "valid":
		return validStyle.Render("valid")
	case "invalid":
		return invalidStyle.Render("invalid")
	case "undetermined":
		return undeterminedStyle.Render("undet")
	default:
		return undeterminedStyle.Render("-")
	}
}

// renderAnnotationStatus returns a styled string for an annotation status.
func renderAnnotationStatus(status string) string {
	switch status {
	case "accept":
		return acceptStyle.Render("accept")
	case "reject":
		return rejectStyle.Render("reject")
	default:
		return ""
	}
}
