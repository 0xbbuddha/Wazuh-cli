package cmd

import (
	"flag"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

func handleDashboard(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	refresh := fs.Int("refresh", 30, "Auto-refresh interval in seconds (0 to disable)")
	if err := fs.Parse(args); err != nil {
		return
	}
	p := tea.NewProgram(newDashModel(*refresh), tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		printErr(fmt.Errorf("dashboard: %w", err))
	}
}
