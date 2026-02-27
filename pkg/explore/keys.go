package explore

import "github.com/charmbracelet/bubbles/key"

type keyMap struct {
	// Navigation
	Up       key.Binding
	Down     key.Binding
	Left     key.Binding
	Right    key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Home     key.Binding
	End      key.Binding

	// Focus switching
	FocusFilters  key.Binding
	FocusFindings key.Binding
	FocusDetails  key.Binding

	// Actions
	ToggleFilter key.Binding
	ResetFilter  key.Binding

	// Annotations
	Accept     key.Binding
	Reject     key.Binding
	AcceptNext key.Binding
	RejectNext key.Binding
	Comment    key.Binding

	// Views
	OpenSource    key.Binding
	ToggleHelp    key.Binding
	ToggleFilters key.Binding

	// Sort
	SortNext key.Binding

	// Quit
	Quit      key.Binding
	ForceQuit key.Binding
}

var defaultKeys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("k/up", "up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("j/dn", "down"),
	),
	Left: key.NewBinding(
		key.WithKeys("left", "h"),
		key.WithHelp("h", "left"),
	),
	Right: key.NewBinding(
		key.WithKeys("right", "l"),
		key.WithHelp("l", "right"),
	),
	PageUp: key.NewBinding(
		key.WithKeys("pgup", "ctrl+b"),
		key.WithHelp("C-b", "page up"),
	),
	PageDown: key.NewBinding(
		key.WithKeys("pgdown", "ctrl+f"),
		key.WithHelp("C-f", "page down"),
	),
	Home: key.NewBinding(
		key.WithKeys("home", "g"),
		key.WithHelp("g", "top"),
	),
	End: key.NewBinding(
		key.WithKeys("end", "G"),
		key.WithHelp("G", "bottom"),
	),
	FocusFilters: key.NewBinding(
		key.WithKeys("f1"),
		key.WithHelp("F1", "filters"),
	),
	FocusFindings: key.NewBinding(
		key.WithKeys("f"),
		key.WithHelp("f", "findings"),
	),
	FocusDetails: key.NewBinding(
		key.WithKeys("d"),
		key.WithHelp("d", "details"),
	),
	ToggleFilter: key.NewBinding(
		key.WithKeys("x", " ", "enter"),
		key.WithHelp("x/spc", "toggle"),
	),
	ResetFilter: key.NewBinding(
		key.WithKeys("ctrl+r"),
		key.WithHelp("C-r", "reset filters"),
	),
	Accept: key.NewBinding(
		key.WithKeys("a"),
		key.WithHelp("a", "accept"),
	),
	Reject: key.NewBinding(
		key.WithKeys("r"),
		key.WithHelp("r", "reject"),
	),
	AcceptNext: key.NewBinding(
		key.WithKeys("A"),
		key.WithHelp("A", "accept+next"),
	),
	RejectNext: key.NewBinding(
		key.WithKeys("R"),
		key.WithHelp("R", "reject+next"),
	),
	Comment: key.NewBinding(
		key.WithKeys("c"),
		key.WithHelp("c", "comment"),
	),
	OpenSource: key.NewBinding(
		key.WithKeys("o"),
		key.WithHelp("o", "source"),
	),
	ToggleHelp: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	ToggleFilters: key.NewBinding(
		key.WithKeys("f7"),
		key.WithHelp("F7", "filters"),
	),
	SortNext: key.NewBinding(
		key.WithKeys("s"),
		key.WithHelp("s", "sort"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q"),
		key.WithHelp("q", "quit"),
	),
	ForceQuit: key.NewBinding(
		key.WithKeys("ctrl+c"),
		key.WithHelp("C-c", "quit"),
	),
}
