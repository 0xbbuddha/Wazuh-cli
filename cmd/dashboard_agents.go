package cmd

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

// ── data messages ─────────────────────────────────────────────────────────────
type agentsDataMsg struct {
	agents []api.Agent
	total  int
}

type arResultMsg struct {
	result  *api.ARResult
	err     error
	action  string
	agentID string
}

// ── AR state machine ──────────────────────────────────────────────────────────
type arState int

const (
	arNone arState = iota
	arSelectAction
	arEnterIP
	arConfirm
	arShowResult
)

// ── tab ───────────────────────────────────────────────────────────────────────
type agentsTab struct {
	all      []api.Agent
	filtered []api.Agent
	total    int
	cursor   int
	offset   int
	loading  bool
	loaded   bool

	searchMode  bool
	searchInput string

	// AR state
	arSt        arState
	arCursor    int
	arAction    string
	arIPInput   string
	arAgentID   string
	arAgentName string
	arResultMsg string
	arResultOK  bool
}

func newAgentsTab() agentsTab { return agentsTab{} }

func agentsLoad() tea.Cmd {
	return func() tea.Msg {
		agAPI := api.NewAgentsAPI(managerClient)
		agents, total, err := agAPI.List("", "", 500, 0)
		if err != nil {
			return agentsDataMsg{}
		}
		return agentsDataMsg{agents: agents, total: total}
	}
}

var agentStatusOrder = map[string]int{
	"active":          0,
	"pending":         1,
	"disconnected":    2,
	"never_connected": 3,
}

func (t agentsTab) applyFilter() agentsTab {
	var out []api.Agent
	if t.searchInput == "" {
		out = make([]api.Agent, len(t.all))
		copy(out, t.all)
	} else {
		q := strings.ToLower(t.searchInput)
		for _, a := range t.all {
			if strings.Contains(strings.ToLower(a.Name), q) ||
				strings.Contains(a.ID, q) ||
				strings.Contains(strings.ToLower(a.Status), q) ||
				strings.Contains(strings.ToLower(a.Os.Name), q) {
				out = append(out, a)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		oi := agentStatusOrder[out[i].Status]
		oj := agentStatusOrder[out[j].Status]
		if oi != oj {
			return oi < oj
		}
		return out[i].Name < out[j].Name
	})
	t.filtered = out
	return t
}

func (t agentsTab) update(msg tea.Msg, _, height int) (agentsTab, *modalModel, tea.Cmd) {
	visH := height - 6
	if visH < 1 {
		visH = 1
	}

	switch msg := msg.(type) {
	case agentsDataMsg:
		t.loading = false
		t.loaded = true
		t.all = msg.agents
		t.total = msg.total
		t = t.applyFilter()
		return t, nil, nil

	case arResultMsg:
		t.arSt = arShowResult
		if msg.err != nil {
			t.arResultMsg = "Error: " + msg.err.Error()
			t.arResultOK = false
		} else if msg.result != nil && msg.result.TotalFailed > 0 {
			f := msg.result.FailedItems[0]
			t.arResultMsg = fmt.Sprintf("[%d] %s", f.Error.Code, f.Error.Message)
			t.arResultOK = false
		} else {
			t.arResultMsg = fmt.Sprintf("Action %q executed on agent %s", msg.action, msg.agentID)
			t.arResultOK = true
		}
		return t, nil, nil

	case tea.KeyMsg:
		if t.arSt != arNone {
			return t.handleARKey(msg)
		}
		if t.searchMode {
			return t.handleSearchKey(msg)
		}
		switch msg.String() {
		case "j", "down":
			if t.cursor < len(t.filtered)-1 {
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
			t.cursor = max(0, len(t.filtered)-1)
			t.offset = max(0, t.cursor-visH+1)
		case "r":
			t.loading = true
			return t, nil, agentsLoad()
		case "/":
			t.searchMode = true
		case "enter":
			if t.cursor < len(t.filtered) {
				return t, agentDetailModal(t.filtered[t.cursor]), nil
			}
		case "a":
			if t.cursor < len(t.filtered) {
				ag := t.filtered[t.cursor]
				t.arSt = arSelectAction
				t.arCursor = 0
				t.arAgentID = ag.ID
				t.arAgentName = ag.Name
				t.arIPInput = ""
				t.arAction = ""
			}
		}
	}
	return t, nil, nil
}

func (t agentsTab) handleSearchKey(msg tea.KeyMsg) (agentsTab, *modalModel, tea.Cmd) {
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

func (t agentsTab) handleARKey(msg tea.KeyMsg) (agentsTab, *modalModel, tea.Cmd) {
	switch t.arSt {
	case arSelectAction:
		switch msg.String() {
		case "j", "down":
			if t.arCursor < len(arActionOrder)-1 {
				t.arCursor++
			}
		case "k", "up":
			if t.arCursor > 0 {
				t.arCursor--
			}
		case "enter":
			t.arAction = arActionOrder[t.arCursor]
			if arActions[t.arAction].needsIP {
				t.arSt = arEnterIP
				t.arIPInput = ""
			} else {
				t.arSt = arConfirm
			}
		case "esc", "q":
			t.arSt = arNone
		}

	case arEnterIP:
		switch msg.String() {
		case "enter":
			if t.arIPInput != "" {
				t.arSt = arConfirm
			}
		case "esc", "q":
			t.arSt = arSelectAction
		case "backspace", "ctrl+h":
			if len(t.arIPInput) > 0 {
				t.arIPInput = t.arIPInput[:len(t.arIPInput)-1]
			}
		case "ctrl+u":
			t.arIPInput = ""
		default:
			if len(msg.Runes) > 0 {
				t.arIPInput += string(msg.Runes)
			}
		}

	case arConfirm:
		switch msg.String() {
		case "y", "enter":
			t.arSt = arNone
			return t, nil, execAR(t.arAgentID, t.arAction, t.arIPInput)
		case "n", "esc", "q":
			t.arSt = arNone
		}

	case arShowResult:
		t.arSt = arNone
	}
	return t, nil, nil
}

func execAR(agentID, actionName, ip string) tea.Cmd {
	return func() tea.Msg {
		action := arActions[actionName]
		req := api.ARRequest{
			Command: action.command,
			Alert:   &api.ARAlert{},
		}
		if ip != "" {
			req.Alert = &api.ARAlert{Data: map[string]string{"srcip": ip}}
		}
		result, err := api.NewActiveResponseAPI(managerClient).Run(agentID, req)
		return arResultMsg{result: result, err: err, action: actionName, agentID: agentID}
	}
}

// ── view ──────────────────────────────────────────────────────────────────────
func (t agentsTab) view(width, height, spinFrame int) string {
	var sb strings.Builder

	// AR panel takes space at the bottom
	arH := 0
	if t.arSt != arNone {
		arH = 10
	}

	sb.WriteString(t.renderSearchBar(width) + "\n")

	if t.searchInput != "" {
		sb.WriteString(dDimStyle.Render(fmt.Sprintf("  %d / %d matched", len(t.filtered), t.total)) + "\n")
	} else {
		sb.WriteString(dDimStyle.Render(fmt.Sprintf("  %d agents", t.total)) + "\n")
	}

	if t.loading {
		sb.WriteString(renderLoading(width, height-2-arH, spinFrame))
		if t.arSt != arNone {
			sb.WriteString("\n" + t.renderARPanel(width))
		}
		return sb.String()
	}

	colHdr := fmt.Sprintf("  %-6s %-20s %-12s %-18s %-12s %s",
		"ID", "NAME", "STATUS", "OS", "VERSION", "LAST SEEN")
	sb.WriteString(dDimStyle.Render(colHdr) + "\n")
	sb.WriteString(dDimStyle.Render("  "+strings.Repeat("─", width-4)) + "\n")

	visH := height - 4 - arH
	if visH < 1 {
		visH = 1
	}

	for i := t.offset; i < t.offset+visH && i < len(t.filtered); i++ {
		a := t.filtered[i]
		statusStr := agentStatusStyle(a.Status).Render(fmt.Sprintf("%-12s", a.Status))
		osName := output.Truncate(a.Os.Name, 16)
		ver := output.Truncate(a.Version, 10)
		seen := fmtLastSeen(a.LastKeepAlive)
		line := fmt.Sprintf("  %-6s %-20s %s %-18s %-12s %s",
			a.ID, output.Truncate(a.Name, 18), statusStr, osName, ver, seen)
		if i == t.cursor {
			line = dSelStyle.Width(width).Render(line)
		}
		sb.WriteString(line + "\n")
	}

	if t.arSt != arNone {
		sb.WriteString(t.renderARPanel(width))
	}

	return sb.String()
}

func (t agentsTab) renderSearchBar(width int) string {
	prefix := dDimStyle.Render("  Filter: ")
	if t.searchMode {
		cur := lipgloss.NewStyle().Foreground(clrPrimary).Render("█")
		box := lipgloss.NewStyle().Background(clrInputBg).
			Width(width - lipgloss.Width(prefix) - 4).
			Render(t.searchInput + cur)
		return prefix + box
	}
	if t.searchInput != "" {
		return prefix +
			lipgloss.NewStyle().Foreground(clrWarn).Render(t.searchInput) +
			dDimStyle.Render("  (/ to edit)")
	}
	return prefix + dDimStyle.Render("press / to filter")
}

func (t agentsTab) renderARPanel(width int) string {
	var sb strings.Builder
	agentLabel := dDimStyle.Render(fmt.Sprintf("  Agent: %s (%s)", t.arAgentName, t.arAgentID))

	switch t.arSt {
	case arSelectAction:
		sb.WriteString(dTitleStyle.Render("  Active Response") + agentLabel + "\n")
		sb.WriteString(dDimStyle.Render("  "+strings.Repeat("─", 52)) + "\n")
		for i, name := range arActionOrder {
			action := arActions[name]
			hint := ""
			if action.needsIP {
				hint = dDimStyle.Render("  <ip>")
			}
			line := fmt.Sprintf("  %-14s %s%s", name, action.description, hint)
			if i == t.arCursor {
				line = lipgloss.NewStyle().Bold(true).Foreground(clrPrimary).
					Background(clrSel).Width(width - 6).Render(line)
			}
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n" + dDimStyle.Render("  ↑↓  select    Enter  confirm    Esc  cancel"))

	case arEnterIP:
		sb.WriteString(dTitleStyle.Render("  "+t.arAction) + agentLabel + "\n")
		sb.WriteString(dDimStyle.Render("  "+strings.Repeat("─", 52)) + "\n\n")
		cur := lipgloss.NewStyle().Foreground(clrPrimary).Render("█")
		box := lipgloss.NewStyle().Background(clrInputBg).Width(22).Render(t.arIPInput + cur)
		sb.WriteString("  " + dDimStyle.Render("IP address: ") + box + "\n\n")
		sb.WriteString(dDimStyle.Render("  Enter  confirm    Esc  back"))

	case arConfirm:
		sb.WriteString(dTitleStyle.Render("  Confirm") + agentLabel + "\n")
		sb.WriteString(dDimStyle.Render("  "+strings.Repeat("─", 52)) + "\n\n")
		sb.WriteString(fmt.Sprintf("  Action : %s\n", dBrightStyle.Render(t.arAction)))
		if arActions[t.arAction].needsIP {
			sb.WriteString(fmt.Sprintf("  IP     : %s\n", dBrightStyle.Render(t.arIPInput)))
		}
		sb.WriteString("\n" + dWarnStyle.Render("  Execute? ") + dDimStyle.Render("[y/N]"))

	case arShowResult:
		sb.WriteString(dTitleStyle.Render("  Result") + "\n")
		sb.WriteString(dDimStyle.Render("  "+strings.Repeat("─", 52)) + "\n\n")
		if t.arResultOK {
			sb.WriteString("  " + dSuccessStyle.Render("✓  "+t.arResultMsg) + "\n")
		} else {
			sb.WriteString("  " + dDangerStyle.Render("✗  "+t.arResultMsg) + "\n")
		}
		sb.WriteString("\n" + dDimStyle.Render("  Press any key to continue"))
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(clrPrimary).
		Width(width - 2).Render(sb.String())
}

// ── agent detail modal ────────────────────────────────────────────────────────
func agentDetailModal(a api.Agent) *modalModel {
	var lines []string
	add := func(k, v string) { lines = append(lines, fmt.Sprintf("%-18s %s", k+":", v)) }
	add("ID", a.ID)
	add("Name", a.Name)
	add("Status", a.Status)
	add("IP", a.IP)
	add("Manager", a.Manager)
	add("Version", a.Version)
	lines = append(lines, "")
	add("OS", a.Os.Name)
	add("OS Version", a.Os.Version)
	add("Platform", a.Os.Platform)
	add("Architecture", a.Os.Arch)
	lines = append(lines, "")
	add("Last Keepalive", a.LastKeepAlive)
	add("Date Added", a.DateAdd)
	if len(a.Group) > 0 {
		add("Groups", strings.Join(a.Group, ", "))
	}
	return &modalModel{
		title: fmt.Sprintf("Agent %s - %s", a.ID, a.Name),
		lines: lines,
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────
func agentStatusStyle(status string) lipgloss.Style {
	switch status {
	case "active":
		return dSuccessStyle
	case "disconnected":
		return dDangerStyle
	case "pending":
		return dWarnStyle
	default:
		return dDimStyle
	}
}

func fmtLastSeen(ts string) string {
	if ts == "" || ts == "N/A" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		if len(ts) >= 10 {
			return ts[:10]
		}
		return ts
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	default:
		return t.Format("2006-01-02")
	}
}
