package cmd

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── palette ───────────────────────────────────────────────────────────────────
var (
	clrPrimary  = lipgloss.Color("39")  // Wazuh blue
	clrSuccess  = lipgloss.Color("46")  // green
	clrWarn     = lipgloss.Color("214") // orange
	clrDanger   = lipgloss.Color("196") // red
	clrHigh     = lipgloss.Color("202") // red-orange
	clrBorder   = lipgloss.Color("240") // panel borders
	clrDim      = lipgloss.Color("245") // dim text (content area)
	clrBarText  = lipgloss.Color("252") // text inside header/status bars
	clrBright   = lipgloss.Color("255") // bright text
	clrBarBg    = lipgloss.Color("236") // header/footer bg — darker for contrast
	clrTabBg    = lipgloss.Color("234") // tab bar bg
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
	tabSCA      = 4
	numTabs     = 5
)

var tabLabels = [numTabs]string{"Overview", "Discover", "Agents", "Vulns", "SCA"}

// ── modal ─────────────────────────────────────────────────────────────────────
type modalModel struct {
	title    string
	lines    []string
	scroll   int
	visLines []string // cached word-wrapped lines
	visMaxW  int      // innerW used when visLines was built
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
	sca           scaTab
	modal         *modalModel
	refreshSecs   int
	spinFrame     int
	now           time.Time
}

func newDashModel(refreshSecs int) dashModel {
	return dashModel{
		refreshSecs: refreshSecs,
		overview:    newOverviewTab(refreshSecs),
		discover:    newDiscoverTab(),
		agents:      newAgentsTab(),
		vulns:       newVulnsTab(),
		sca:         newScaTab(),
		now:         time.Now(),
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
		m.now = time.Now()
		var cmds []tea.Cmd
		cmds = append(cmds, dashTick(msg.frame))
		var cmd tea.Cmd
		m.overview, _, cmd = m.overview.update(msg, m.width, m.height)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)

	case tea.MouseMsg:
		return m.handleMouse(msg)

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
		case "5":
			return m.switchTab(tabSCA)
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
	case tabSCA:
		return m.sca.searchMode
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
	case tabSCA:
		if !m.sca.agentsLoaded {
			m.sca.agentsLoading = true
			return m, scaLoadAgents()
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
	case tabSCA:
		m.sca, modal, cmd = m.sca.update(msg, m.width, m.height)
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
	case tabSCA:
		content = m.sca.view(m.width, contentH, m.spinFrame)
	}

	// Force content to exactly contentH lines: truncate if too tall, pad if too short
	content = fitHeight(content, contentH)

	return strings.Join([]string{
		m.renderHeader(),
		m.renderTabBar(),
		content,
		m.renderStatusBar(),
	}, "\n")
}

// ── mouse ─────────────────────────────────────────────────────────────────────
func (m dashModel) handleMouse(msg tea.MouseMsg) (dashModel, tea.Cmd) {
	switch {
	case msg.Button == tea.MouseButtonWheelUp && msg.Action == tea.MouseActionPress:
		if m.modal != nil {
			if m.modal.scroll > 0 {
				m.modal.scroll--
			}
			return m, nil
		}
		return m.routeToActiveTab(tea.KeyMsg{Type: tea.KeyUp})

	case msg.Button == tea.MouseButtonWheelDown && msg.Action == tea.MouseActionPress:
		if m.modal != nil {
			m.modal.scroll++
			return m, nil
		}
		return m.routeToActiveTab(tea.KeyMsg{Type: tea.KeyDown})

	case msg.Button == tea.MouseButtonLeft && msg.Action == tea.MouseActionPress:
		if m.modal != nil {
			return m, nil
		}
		if msg.Y == 1 {
			return m.handleTabBarClick(msg.X)
		}
		if msg.Y >= 6 {
			m = m.handleListClick(msg.Y)
		}
	}
	return m, nil
}

func (m dashModel) handleTabBarClick(x int) (dashModel, tea.Cmd) {
	pos := 0
	for i, name := range tabLabels {
		label := fmt.Sprintf("  %d:%s  ", i+1, name)
		w := len([]rune(label))
		if x >= pos && x < pos+w {
			return m.switchTab(i)
		}
		pos += w + 1 // +1 for │ separator
	}
	return m, nil
}

// handleListClick maps a Y click position to a cursor row.
// Content starts at Y=2 (header+tabbar), list rows start at Y=6 (4 header lines per tab).
func (m dashModel) handleListClick(y int) dashModel {
	row := y - 6
	if row < 0 {
		return m
	}
	switch m.activeTab {
	case tabDiscover:
		target := m.discover.offset + row
		if target < len(m.discover.alerts) {
			m.discover.cursor = target
		}
	case tabAgents:
		target := m.agents.offset + row
		if target < len(m.agents.filtered) {
			m.agents.cursor = target
		}
	case tabVulns:
		target := m.vulns.offset + row
		if target < len(m.vulns.vulns) {
			m.vulns.cursor = target
		}
	case tabSCA:
		target := m.sca.offset + row
		if m.sca.state == scaViewAgents && target < len(m.sca.agentsFilt) {
			m.sca.cursor = target
		} else if m.sca.state == scaViewPolicies && target < len(m.sca.policies) {
			m.sca.cursor = target
		}
	}
	return m
}

// ── header ────────────────────────────────────────────────────────────────────
func (m dashModel) renderHeader() string {
	logo := lipgloss.NewStyle().Bold(true).Foreground(clrPrimary).Render("  WAZUH-CLI")
	clock := lipgloss.NewStyle().Foreground(clrBarText).Render(m.now.Format("15:04:05"))
	right := lipgloss.NewStyle().Foreground(clrBarText).Render("Interactive Dashboard  ")
	mid := clock
	gap1 := (m.width-lipgloss.Width(logo)-lipgloss.Width(mid)-lipgloss.Width(right))/2
	if gap1 < 1 {
		gap1 = 1
	}
	gap2 := m.width - lipgloss.Width(logo) - gap1 - lipgloss.Width(mid) - lipgloss.Width(right)
	if gap2 < 1 {
		gap2 = 1
	}
	return lipgloss.NewStyle().Background(clrBarBg).Width(m.width).
		Render(logo + strings.Repeat(" ", gap1) + mid + strings.Repeat(" ", gap2) + right)
}

// ── tab bar ───────────────────────────────────────────────────────────────────
func (m dashModel) renderTabBar() string {
	var parts []string
	for i, name := range tabLabels {
		label := fmt.Sprintf("  %d:%s  ", i+1, name)
		if i == m.activeTab {
			parts = append(parts, lipgloss.NewStyle().Bold(true).
				Foreground(clrPrimary).Background(lipgloss.Color("238")).
				Render(label))
		} else {
			parts = append(parts, lipgloss.NewStyle().
				Foreground(lipgloss.Color("250")).
				Render(label))
		}
		if i < numTabs-1 {
			parts = append(parts, lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("│"))
		}
	}
	return lipgloss.NewStyle().Background(clrTabBg).Width(m.width).Render(strings.Join(parts, ""))
}

// ── status bar ────────────────────────────────────────────────────────────────
func (m dashModel) renderStatusBar() string {
	barDesc := lipgloss.NewStyle().Foreground(clrBarText)
	key := func(k, desc string) string {
		return lipgloss.NewStyle().Bold(true).Foreground(clrPrimary).Render(k) + " " + barDesc.Render(desc)
	}
	hints := []string{key("1-5", "tabs"), key("Tab", "next"), key("q", "quit")}
	switch m.activeTab {
	case tabDiscover:
		hints = append(hints, key("/", "search"), key("f", "level"), key("↑↓", "nav"), key("Enter", "detail"), key("r", "refresh"))
	case tabAgents:
		hints = append(hints, key("/", "filter"), key("↑↓", "nav"), key("Enter", "detail"), key("a", "AR"), key("r", "refresh"))
	case tabVulns:
		hints = append(hints, key("f", "severity"), key("↑↓", "nav"), key("Enter", "detail"), key("r", "refresh"))
	case tabOverview:
		hints = append(hints, key("r", "refresh"))
	case tabSCA:
		hints = append(hints, key("/", "filter"), key("↑↓", "nav"), key("Enter", "select"), key("Esc", "back"), key("r", "refresh"))
	}
	return lipgloss.NewStyle().Background(clrBarBg).Width(m.width).Render("  " + strings.Join(hints, "   "))
}

// ── modal view ────────────────────────────────────────────────────────────────
func (m dashModel) renderModalView() string {
	modal := m.modal
	mW := m.width * 9 / 10
	if mW > 180 {
		mW = 180
	}
	if mW < 40 {
		mW = 40
	}
	innerW := mW - 6
	innerH := m.height*4/5 - 6
	if innerH < 4 {
		innerH = 4
	}

	// Build (or reuse) the cached word-wrapped line list
	if modal.visLines == nil || modal.visMaxW != innerW {
		modal.visLines = modal.visLines[:0]
		for _, line := range modal.lines {
			modal.visLines = append(modal.visLines, wrapModalLine(line, innerW)...)
		}
		modal.visMaxW = innerW
	}
	visLines := modal.visLines

	// Clamp scroll to visual line count
	maxScroll := max(0, len(visLines)-innerH)
	if modal.scroll > maxScroll {
		modal.scroll = maxScroll
	}
	end := modal.scroll + innerH
	if end > len(visLines) {
		end = len(visLines)
	}

	var sb strings.Builder
	for _, line := range visLines[modal.scroll:end] {
		sb.WriteString(line + "\n")
	}

	scrollHint := ""
	if len(visLines) > innerH {
		pct := 0
		if len(visLines) > 0 {
			pct = min((modal.scroll+innerH)*100/len(visLines), 100)
		}
		scrollHint = dDimStyle.Render(fmt.Sprintf("  [%d/%d · %d%%]", modal.scroll+1, len(visLines), pct))
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(clrPrimary).
		Width(mW).Padding(1, 2).
		Render(
			dTitleStyle.Render("  "+modal.title)+scrollHint+"\n"+
				dDimStyle.Render(strings.Repeat("─", innerW))+"\n\n"+
				strings.TrimRight(sb.String(), "\n")+"\n\n"+
				dDimStyle.Render("esc/q  close    ↑↓ · jk · scroll wheel  scroll"),
		)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

// wrapModalLine word-wraps a line at maxW visible characters.
// Lines with ANSI codes are truncated; plain text is word-wrapped.
// All operations are rune-safe.
func wrapModalLine(line string, maxW int) []string {
	if maxW < 1 {
		return []string{line}
	}
	visW := lipgloss.Width(line)
	if visW <= maxW {
		return []string{line}
	}
	runes := []rune(line)
	// Has ANSI codes — truncate by rune count
	if visW != len(runes) {
		if len(runes) > maxW {
			return []string{string(runes[:maxW])}
		}
		return []string{line}
	}
	// Plain text — word wrap by rune
	var result []string
	for len(runes) > maxW {
		cut := maxW
		for i := maxW - 1; i > 0; i-- {
			if runes[i] == ' ' {
				cut = i
				break
			}
		}
		result = append(result, string(runes[:cut]))
		// skip leading spaces on next segment
		for cut < len(runes) && runes[cut] == ' ' {
			cut++
		}
		runes = runes[cut:]
		if len(runes) == 0 {
			break
		}
	}
	if len(runes) > 0 {
		result = append(result, string(runes))
	}
	return result
}

// fitHeight forces s to exactly h lines: truncates if too tall, pads if too short.
func fitHeight(s string, h int) string {
	if h <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	// Remove all trailing empty strings produced by trailing \n's
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > h {
		lines = lines[:h]
	} else {
		for len(lines) < h {
			lines = append(lines, "")
		}
	}
	return strings.Join(lines, "\n")
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

