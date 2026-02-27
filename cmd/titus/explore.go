package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/praetorian-inc/titus/pkg/explore"
	"github.com/spf13/cobra"
)

var (
	exploreDatastore string
)

var exploreCmd = &cobra.Command{
	Use:   "explore",
	Short: "Interactively explore scan results",
	Long: `Launch an interactive TUI to browse findings from a scan datastore.

Features:
  - Three-pane layout: filters, findings table, match details
  - Faceted search by rule name, category, and validation status
  - Accept/reject annotations with comments
  - Vi-style navigation (hjkl, Ctrl-f/b, g/G)
  - Source viewer for matched content
  - Sortable findings table`,
	RunE: runExplore,
}

func init() {
	exploreCmd.Flags().StringVar(&exploreDatastore, "datastore", "titus.ds", "Path to datastore directory or file")
}

func runExplore(cmd *cobra.Command, args []string) error {
	model, err := explore.New(exploreDatastore)
	if err != nil {
		return fmt.Errorf("loading datastore: %w", err)
	}
	defer model.Close()

	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("running explore TUI: %w", err)
	}

	return nil
}
