package cmd

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

// ── view state ────────────────────────────────────────────────────────────────
type scaViewState int

const (
	scaViewAgents   scaViewState = iota
	scaViewPolicies
)

// ── data messages ─────────────────────────────────────────────────────────────
type scaAgentsDataMsg struct {
	agents []api.Agent
	total  int
}

type scaPoliciesDataMsg struct {
	agentID  string
	policies []api.SCAPolicy
}

type scaChecksDataMsg struct {
	policyName string
	checks     []api.SCACheck
	total      int
}

// ── tab ───────────────────────────────────────────────────────────────────────
type scaTab struct {
	state scaViewState

	agents       []api.Agent
	agentsFilt   []api.Agent
	agentsTotal  int
	agentsLoading bool
	agentsLoaded  bool

	selectedAgent *api.Agent
	policies      []api.SCAPolicy
	polLoading    bool

	cursor      int
	offset      int
	searchInput string
	searchMode  bool
}

func newScaTab() scaTab { return scaTab{} }

// ── loaders ───────────────────────────────────────────────────────────────────
func scaLoadAgents() tea.Cmd {
	return func() tea.Msg {
		agAPI := api.NewAgentsAPI(managerClient)
		agents, total, err := agAPI.List("", "", 500, 0)
		if err != nil {
			return scaAgentsDataMsg{}
		}
		return scaAgentsDataMsg{agents: agents, total: total}
	}
}

func scaLoadPolicies(agentID string) tea.Cmd {
	return func() tea.Msg {
		s := api.NewSCAAPI(managerClient)
		policies, err := s.List(agentID)
		if err != nil {
			return scaPoliciesDataMsg{agentID: agentID}
		}
		return scaPoliciesDataMsg{agentID: agentID, policies: policies}
	}
}

func scaLoadChecks(agentID, policyID, policyName string) tea.Cmd {
	return func() tea.Msg {
		s := api.NewSCAAPI(managerClient)
		checks, total, err := s.Checks(agentID, policyID)
		if err != nil {
			return scaChecksDataMsg{policyName: policyName}
		}
		return scaChecksDataMsg{policyName: policyName, checks: checks, total: total}
	}
}

// ── filter ────────────────────────────────────────────────────────────────────
func (t scaTab) applyFilter() scaTab {
	if t.searchInput == "" {
		t.agentsFilt = t.agents
		return t
	}
	q := strings.ToLower(t.searchInput)
	var out []api.Agent
	for _, a := range t.agents {
		if strings.Contains(strings.ToLower(a.Name), q) ||
			strings.Contains(a.ID, q) {
			out = append(out, a)
		}
	}
	t.agentsFilt = out
	return t
}

// ── update ────────────────────────────────────────────────────────────────────
func (t scaTab) update(msg tea.Msg, _, height int) (scaTab, *modalModel, tea.Cmd) {
	visH := height - 5
	if t.state == scaViewPolicies {
		visH = height - 4
	}
	if visH < 1 {
		visH = 1
	}

	currentLen := len(t.agentsFilt)
	if t.state == scaViewPolicies {
		currentLen = len(t.policies)
	}

	switch msg := msg.(type) {
	case scaAgentsDataMsg:
		t.agentsLoading = false
		t.agentsLoaded = true
		t.agents = msg.agents
		t.agentsTotal = msg.total
		t = t.applyFilter()
		return t, nil, nil

	case scaPoliciesDataMsg:
		t.polLoading = false
		t.policies = msg.policies
		t.cursor, t.offset = 0, 0
		return t, nil, nil

	case scaChecksDataMsg:
		return t, scaChecksModal(msg.policyName, msg.checks, msg.total), nil

	case tea.KeyMsg:
		if t.searchMode {
			return t.handleSearchKey(msg)
		}
		switch msg.String() {
		case "j", "down":
			if t.cursor < currentLen-1 {
				t.cursor++
				if t.cursor >= t.offset+visH {
					t.offset++
				}
			}
		case "k", "up":
			if t.cursor > 0 {
				t.cursor--
				if t.cursor < t.offset {
					t.offset = t.cursor
				}
			}
		case "g":
			t.cursor, t.offset = 0, 0
		case "G":
			t.cursor = max(0, currentLen-1)
			t.offset = max(0, t.cursor-visH+1)
		case "r":
			t.cursor, t.offset = 0, 0
			if t.state == scaViewAgents {
				t.agentsLoading = true
				return t, nil, scaLoadAgents()
			}
			if t.selectedAgent != nil {
				t.polLoading = true
				return t, nil, scaLoadPolicies(t.selectedAgent.ID)
			}
		case "/":
			if t.state == scaViewAgents {
				t.searchMode = true
			}
		case "esc", "backspace":
			if t.state == scaViewPolicies {
				t.state = scaViewAgents
				t.cursor, t.offset = 0, 0
			}
		case "enter":
			if t.state == scaViewAgents && t.cursor < len(t.agentsFilt) {
				ag := t.agentsFilt[t.cursor]
				t.selectedAgent = &ag
				t.state = scaViewPolicies
				t.polLoading = true
				t.cursor, t.offset = 0, 0
				return t, nil, scaLoadPolicies(ag.ID)
			}
			if t.state == scaViewPolicies && t.cursor < len(t.policies) && t.selectedAgent != nil {
				pol := t.policies[t.cursor]
				return t, nil, scaLoadChecks(t.selectedAgent.ID, pol.PolicyID, pol.Name)
			}
		}
	}
	return t, nil, nil
}

func (t scaTab) handleSearchKey(msg tea.KeyMsg) (scaTab, *modalModel, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		t.searchMode = false
	case "backspace", "ctrl+h":
		if len(t.searchInput) > 0 {
			t.searchInput = t.searchInput[:len(t.searchInput)-1]
			t = t.applyFilter()
			t.cursor, t.offset = 0, 0
		}
	case "ctrl+u":
		t.searchInput = ""
		t = t.applyFilter()
		t.cursor, t.offset = 0, 0
	default:
		if len(msg.Runes) > 0 {
			t.searchInput += string(msg.Runes)
			t = t.applyFilter()
			t.cursor, t.offset = 0, 0
		}
	}
	return t, nil, nil
}

// ── view ──────────────────────────────────────────────────────────────────────
func (t scaTab) view(width, height, spinFrame int) string {
	if t.state == scaViewPolicies {
		return t.viewPolicies(width, height, spinFrame)
	}
	return t.viewAgents(width, height, spinFrame)
}

func (t scaTab) viewAgents(width, height, spinFrame int) string {
	var sb strings.Builder

	prefix := dDimStyle.Render("  Filter: ")
	if t.searchMode {
		cur := lipgloss.NewStyle().Foreground(clrPrimary).Render("█")
		box := lipgloss.NewStyle().Background(clrInputBg).
			Width(width - lipgloss.Width(prefix) - 4).
			Render(t.searchInput + cur)
		sb.WriteString(prefix + box + "\n")
	} else if t.searchInput != "" {
		sb.WriteString(prefix +
			lipgloss.NewStyle().Foreground(clrWarn).Render(t.searchInput) +
			dDimStyle.Render("  (/ to edit)") + "\n")
	} else {
		sb.WriteString(prefix + dDimStyle.Render("press / to filter - Enter to drill into SCA policies") + "\n")
	}

	if t.agentsLoading || !t.agentsLoaded {
		sb.WriteString(renderLoading(width, height-2, spinFrame))
		return sb.String()
	}

	list := t.agentsFilt
	count := fmt.Sprintf("  %d agents", len(list))
	if t.searchInput != "" {
		count = fmt.Sprintf("  %d / %d matched", len(list), t.agentsTotal)
	}
	sb.WriteString(dDimStyle.Render(count) + "\n")
	colHdr := fmt.Sprintf("  %-6s %-22s %-14s %s", "ID", "NAME", "STATUS", "OS")
	sb.WriteString(dDimStyle.Render(colHdr) + "\n")
	sb.WriteString(dDimStyle.Render("  "+strings.Repeat("─", width-4)) + "\n")

	if len(list) == 0 {
		sb.WriteString("\n  " + dDimStyle.Render("No agents found"))
		return sb.String()
	}

	visH := height - 5
	if visH < 1 {
		visH = 1
	}
	for i := t.offset; i < t.offset+visH && i < len(list); i++ {
		a := list[i]
		statusStr := agentStatusStyle(a.Status).Render(fmt.Sprintf("%-14s", a.Status))
		osStr := output.Truncate(a.Os.Name, 22)
		line := fmt.Sprintf("  %-6s %-22s %s %s",
			a.ID, output.Truncate(a.Name, 20), statusStr, osStr)
		if i == t.cursor {
			line = dSelStyle.Width(width).Render(line)
		}
		sb.WriteString(line + "\n")
	}
	return sb.String()
}

func (t scaTab) viewPolicies(width, height, spinFrame int) string {
	var sb strings.Builder

	agentLabel := ""
	if t.selectedAgent != nil {
		agentLabel = dBrightStyle.Render(t.selectedAgent.Name) +
			dDimStyle.Render("  ("+t.selectedAgent.ID+")")
	}
	sb.WriteString("  " + dTitleStyle.Render("SCA Policies") + "  " + agentLabel + "\n")
	sb.WriteString(dDimStyle.Render("  Esc ← agents    Enter → view checks") + "\n")

	if t.polLoading {
		sb.WriteString(renderLoading(width, height-3, spinFrame))
		return sb.String()
	}
	if len(t.policies) == 0 {
		sb.WriteString("\n  " + dDimStyle.Render("No SCA policies found for this agent"))
		return sb.String()
	}

	colHdr := fmt.Sprintf("  %-28s %-7s %6s %6s %6s  %s",
		"POLICY NAME", "SCORE", "PASS", "FAIL", "N/A", "LAST SCAN")
	sb.WriteString(dDimStyle.Render(colHdr) + "\n")
	sb.WriteString(dDimStyle.Render("  "+strings.Repeat("─", width-4)) + "\n")

	visH := height - 4
	if visH < 1 {
		visH = 1
	}
	for i := t.offset; i < t.offset+visH && i < len(t.policies); i++ {
		p := t.policies[i]
		scoreStyle := dSuccessStyle
		if p.Score < 80 {
			scoreStyle = dWarnStyle
		}
		if p.Score < 50 {
			scoreStyle = dDangerStyle
		}
		scanDate := "-"
		if len(p.EndScan) >= 10 {
			scanDate = p.EndScan[:10]
		}
		line := fmt.Sprintf("  %-28s %s  %6d %6d %6d  %s",
			output.Truncate(p.Name, 26),
			scoreStyle.Render(fmt.Sprintf("%3d%%", p.Score)),
			p.PassCount, p.FailCount, p.InvalidCount,
			dDimStyle.Render(scanDate))
		if i == t.cursor {
			line = dSelStyle.Width(width).Render(line)
		}
		sb.WriteString(line + "\n")
	}
	return sb.String()
}

// ── checks modal ──────────────────────────────────────────────────────────────
func scaChecksModal(policyName string, checks []api.SCACheck, total int) *modalModel {
	var lines []string

	passed, failed, na := 0, 0, 0
	for _, ch := range checks {
		switch ch.Result {
		case "passed":
			passed++
		case "failed":
			failed++
		default:
			na++
		}
	}
	lines = append(lines, fmt.Sprintf("  %s %d passed   %s %d failed   %s %d N/A",
		dSuccessStyle.Render("✓"), passed,
		dDangerStyle.Render("✗"), failed,
		dDimStyle.Render("-"), na))
	lines = append(lines, "")
	lines = append(lines, dDimStyle.Render(strings.Repeat("─", 62)))
	lines = append(lines, "")

	for _, ch := range checks {
		var badge string
		var st lipgloss.Style
		switch ch.Result {
		case "passed":
			badge, st = "✓", dSuccessStyle
		case "failed":
			badge, st = "✗", dDangerStyle
		default:
			badge, st = "-", dDimStyle
		}
		lines = append(lines, st.Render(fmt.Sprintf(" %s [%d] %s", badge, ch.ID, output.Truncate(ch.Title, 58))))
		if ch.Result == "failed" && ch.Remediation != "" {
			lines = append(lines, dDimStyle.Render("     → "+output.Truncate(ch.Remediation, 56)))
		}
	}
	return &modalModel{title: policyName, lines: lines}
}
