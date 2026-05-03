package cmd

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// ── palette ───────────────────────────────────────────────────────────────────
var (
	clrPrimary  = lipgloss.Color("39")  // Wazuh blue
	clrSuccess  = lipgloss.Color("46")  // green
	clrWarn     = lipgloss.Color("214") // orange
	clrDanger   = lipgloss.Color("196") // red
	clrHigh     = lipgloss.Color("202") // red-orange
	clrBorder   = lipgloss.Color("240") // panel borders
	clrDim      = lipgloss.Color("245") // dim text
	clrBright   = lipgloss.Color("255") // bright text
	clrBarBg    = lipgloss.Color("235") // header/footer bg
	clrTabBg    = lipgloss.Color("233") // tab bar bg
	clrSel      = lipgloss.Color("237") // selected row bg
	clrInputBg  = lipgloss.Color("236") // search input bg

	dPanelStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(clrBorder).Padding(0, 1)
	dTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(clrPrimary)
	dDimStyle     = lipgloss.NewStyle().Foreground(clrDim)
	dBrightStyle  = lipgloss.NewStyle().Bold(true).Foreground(clrBright)
	dSuccessStyle = lipgloss.NewStyle().Foreground(clrSuccess)
	dWarnStyle    = lipgloss.NewStyle().Foreground(clrWarn)
	dDangerStyle  = lipgloss.NewStyle().Bold(true).Foreground(clrDanger)
	dSelStyle     = lipgloss.NewStyle().Background(clrSel)

	dSevStyles = map[string]lipgloss.Style{
		"critical": lipgloss.NewStyle().Bold(true).Foreground(clrDanger),
		"high":     lipgloss.NewStyle().Foreground(clrHigh),
		"medium":   lipgloss.NewStyle().Foreground(clrWarn),
		"low":      lipgloss.NewStyle().Foreground(clrSuccess),
	}
)

// ── tabs ──────────────────────────────────────────────────────────────────────
const (
	tabOverview = 0
	tabDiscover = 1
	tabAgents   = 2
	tabVulns    = 3
	numTabs     = 4
)

var tabLabels = [numTabs]string{"Overview", "Discover", "Agents", "Vulns"}

// ── modal ─────────────────────────────────────────────────────────────────────
type modalModel struct {
	title  string
	lines  []string
	scroll int
}

// ── tick ──────────────────────────────────────────────────────────────────────
type dashTickMsg struct{ frame int }

func dashTick(frame int) tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(_ time.Time) tea.Msg {
		return dashTickMsg{frame: (frame + 1) % 10}
	})
}

var dashSpinChars = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ── main model ────────────────────────────────────────────────────────────────
type dashModel struct {
	width, height int
	activeTab     int
	overview      overviewTab
	discover      discoverTab
	agents        agentsTab
	vulns         vulnsTab
	modal         *modalModel
	refreshSecs   int
	spinFrame     int
}

func newDashModel(refreshSecs int) dashModel {
	return dashModel{
		refreshSecs: refreshSecs,
		overview:    newOverviewTab(refreshSecs),
		discover:    newDiscoverTab(),
		agents:      newAgentsTab(),
		vulns:       newVulnsTab(),
	}
}

func (m dashModel) Init() tea.Cmd {
	return tea.Batch(m.overview.init(), dashTick(0))
}

func (m dashModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case dashTickMsg:
		m.spinFrame = msg.frame
		var cmds []tea.Cmd
		cmds = append(cmds, dashTick(msg.frame))
		// Always propagate tick to overview for auto-refresh
		var cmd tea.Cmd
		m.overview, _, cmd = m.overview.update(msg, m.width, m.height)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)

	case tea.KeyMsg:
		if m.modal != nil {
			return m.handleModalKey(msg)
		}
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if msg.String() == "q" && !m.tabIsCapturingInput() {
			return m, tea.Quit
		}
		// Tab switches
		switch msg.String() {
		case "1":
			m.activeTab = tabOverview
			return m, nil
		case "2":
			return m.switchTab(tabDiscover)
		case "3":
			return m.switchTab(tabAgents)
		case "4":
			return m.switchTab(tabVulns)
		case "tab":
			return m.switchTab((m.activeTab + 1) % numTabs)
		case "shift+tab":
			return m.switchTab((m.activeTab - 1 + numTabs) % numTabs)
		}
	}

	return m.routeToActiveTab(msg)
}

func (m dashModel) handleModalKey(msg tea.KeyMsg) (dashModel, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "enter":
		m.modal = nil
	case "j", "down":
		m.modal.scroll++
	case "k", "up":
		if m.modal.scroll > 0 {
			m.modal.scroll--
		}
	}
	return m, nil
}

func (m dashModel) tabIsCapturingInput() bool {
	switch m.activeTab {
	case tabDiscover:
		return m.discover.searchMode
	case tabAgents:
		return m.agents.searchMode || m.agents.arSt != arNone
	}
	return false
}

func (m dashModel) switchTab(tab int) (dashModel, tea.Cmd) {
	m.activeTab = tab
	switch tab {
	case tabDiscover:
		if !m.discover.loaded {
			m.discover.loading = true
			return m, discoverLoad(m.discover)
		}
	case tabAgents:
		if !m.agents.loaded {
			m.agents.loading = true
			return m, agentsLoad()
		}
	case tabVulns:
		if !m.vulns.loaded {
			m.vulns.loading = true
			return m, vulnsLoad(m.vulns)
		}
	}
	return m, nil
}

func (m dashModel) routeToActiveTab(msg tea.Msg) (dashModel, tea.Cmd) {
	var modal *modalModel
	var cmd tea.Cmd
	switch m.activeTab {
	case tabOverview:
		m.overview, modal, cmd = m.overview.update(msg, m.width, m.height)
	case tabDiscover:
		m.discover, modal, cmd = m.discover.update(msg, m.width, m.height)
	case tabAgents:
		m.agents, modal, cmd = m.agents.update(msg, m.width, m.height)
	case tabVulns:
		m.vulns, modal, cmd = m.vulns.update(msg, m.width, m.height)
	}
	if modal != nil {
		m.modal = modal
	}
	return m, cmd
}

// ── view ──────────────────────────────────────────────────────────────────────
func (m dashModel) View() string {
	if m.width == 0 {
		return ""
	}
	if m.modal != nil {
		return m.renderModalView()
	}

	contentH := m.height - 3
	if contentH < 4 {
		contentH = 4
	}

	var content string
	switch m.activeTab {
	case tabOverview:
		content = m.overview.view(m.width, contentH, m.spinFrame)
	case tabDiscover:
		content = m.discover.view(m.width, contentH, m.spinFrame)
	case tabAgents:
		content = m.agents.view(m.width, contentH, m.spinFrame)
	case tabVulns:
		content = m.vulns.view(m.width, contentH, m.spinFrame)
	}

	return strings.Join([]string{
		m.renderHeader(),
		m.renderTabBar(),
		content,
		m.renderStatusBar(),
	}, "\n")
}

// ── header ────────────────────────────────────────────────────────────────────
func (m dashModel) renderHeader() string {
	logo := lipgloss.NewStyle().Bold(true).Foreground(clrPrimary).Render("  WAZUH-CLI")
	right := dDimStyle.Render("Interactive Dashboard  ")
	gap := m.width - lipgloss.Width(logo) - lipgloss.Width(right)
	if gap < 0 {
		gap = 0
	}
	return lipgloss.NewStyle().Background(clrBarBg).Width(m.width).
		Render(logo + strings.Repeat(" ", gap) + right)
}

// ── tab bar ───────────────────────────────────────────────────────────────────
func (m dashModel) renderTabBar() string {
	var parts []string
	for i, name := range tabLabels {
		label := fmt.Sprintf("  %d:%s  ", i+1, name)
		if i == m.activeTab {
			parts = append(parts, lipgloss.NewStyle().Bold(true).Foreground(clrPrimary).Render(label))
		} else {
			parts = append(parts, dDimStyle.Render(label))
		}
		if i < numTabs-1 {
			parts = append(parts, dDimStyle.Render("│"))
		}
	}
	return lipgloss.NewStyle().Background(clrTabBg).Width(m.width).Render(strings.Join(parts, ""))
}

// ── status bar ────────────────────────────────────────────────────────────────
func (m dashModel) renderStatusBar() string {
	key := func(k, desc string) string {
		return lipgloss.NewStyle().Bold(true).Foreground(clrPrimary).Render(k) + " " + dDimStyle.Render(desc)
	}
	hints := []string{key("1-4", "tabs"), key("Tab", "next"), key("q", "quit")}
	switch m.activeTab {
	case tabDiscover:
		hints = append(hints, key("/", "search"), key("f", "level"), key("↑↓", "nav"), key("Enter", "detail"), key("r", "refresh"))
	case tabAgents:
		hints = append(hints, key("/", "filter"), key("↑↓", "nav"), key("Enter", "detail"), key("a", "active-response"), key("r", "refresh"))
	case tabVulns:
		hints = append(hints, key("f", "severity"), key("↑↓", "nav"), key("Enter", "detail"), key("r", "refresh"))
	case tabOverview:
		hints = append(hints, key("r", "refresh"))
	}
	return lipgloss.NewStyle().Background(clrBarBg).Width(m.width).Render("  " + strings.Join(hints, "   "))
}

// ── modal view ────────────────────────────────────────────────────────────────
func (m dashModel) renderModalView() string {
	modal := m.modal
	mW := m.width * 3 / 4
	if mW > 120 {
		mW = 120
	}
	if mW < 40 {
		mW = 40
	}
	innerW := mW - 6
	innerH := m.height*2/3 - 8
	if innerH < 4 {
		innerH = 4
	}

	// Clamp scroll
	if modal.scroll+innerH > len(modal.lines) {
		modal.scroll = max(0, len(modal.lines)-innerH)
	}
	end := modal.scroll + innerH
	if end > len(modal.lines) {
		end = len(modal.lines)
	}

	var sb strings.Builder
	for _, line := range modal.lines[modal.scroll:end] {
		if lipgloss.Width(line) > innerW {
			runes := []rune(line)
			if len(runes) > innerW {
				line = string(runes[:innerW])
			}
		}
		sb.WriteString(line + "\n")
	}

	scrollHint := ""
	if len(modal.lines) > innerH {
		scrollHint = dDimStyle.Render(fmt.Sprintf(" [%d/%d]", modal.scroll+1, len(modal.lines)))
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(clrPrimary).
		Width(mW).Padding(1, 2).
		Render(
			dTitleStyle.Render("  "+modal.title)+scrollHint+"\n"+
				dDimStyle.Render(strings.Repeat("─", innerW))+"\n\n"+
				strings.TrimRight(sb.String(), "\n")+"\n\n"+
				dDimStyle.Render("esc · q  close    ↑↓ · jk  scroll"),
		)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

// ── shared helpers ────────────────────────────────────────────────────────────
func dashFmt(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func renderLoading(w, h, frame int) string {
	if frame < 0 || frame >= len(dashSpinChars) {
		frame = 0
	}
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center,
		dDimStyle.Render(dashSpinChars[frame]+" Loading..."))
}

// ── command ───────────────────────────────────────────────────────────────────
func newDashboardCmd() *cobra.Command {
	var refreshSecs int
	cmd := &cobra.Command{
		Use:     "dashboard",
		Short:   "Interactive TUI dashboard (agents, alerts, vulnerabilities)",
		Aliases: []string{"dash"},
		Run: func(cmd *cobra.Command, args []string) {
			p := tea.NewProgram(newDashModel(refreshSecs), tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				die(err)
			}
		},
	}
	cmd.Flags().IntVar(&refreshSecs, "refresh", 30, "Auto-refresh interval in seconds (0 to disable)")
	return cmd
}
