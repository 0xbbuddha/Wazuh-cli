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
type fimViewState int

const (
	fimViewAgents fimViewState = iota
	fimViewEvents
)

// ── event filter ──────────────────────────────────────────────────────────────
var fimEventFilters = []string{"all", "modified", "added", "deleted"}

// ── data messages ─────────────────────────────────────────────────────────────
type fimAgentsDataMsg struct {
	agents []api.Agent
}

type fimEventsDataMsg struct {
	agentID string
	files   []api.SyscheckFile
	total   int
}

// ── tab ───────────────────────────────────────────────────────────────────────
type fimTab struct {
	state fimViewState

	agents        []api.Agent
	agentsFilt    []api.Agent
	agentsLoading bool
	agentsLoaded  bool

	selectedAgent *api.Agent
	allFiles      []api.SyscheckFile
	files         []api.SyscheckFile
	total         int
	eventsLoading bool

	filterIdx   int // index into fimEventFilters
	cursor      int
	offset      int
	searchInput string
	searchMode  bool
}

func newFimTab() fimTab { return fimTab{} }

// ── loaders ───────────────────────────────────────────────────────────────────
func fimLoadAgents() tea.Cmd {
	return func() tea.Msg {
		agAPI := api.NewAgentsAPI(managerClient)
		agents, _, err := agAPI.List("active", "", 500, 0)
		if err != nil {
			return fimAgentsDataMsg{}
		}
		return fimAgentsDataMsg{agents: agents}
	}
}

func fimLoadEvents(agentID string) tea.Cmd {
	return func() tea.Msg {
		sc := api.NewSyscheckAPI(managerClient)
		files, total, err := sc.Files(agentID, "", "", 500, 0)
		if err != nil {
			return fimEventsDataMsg{agentID: agentID}
		}
		return fimEventsDataMsg{agentID: agentID, files: files, total: total}
	}
}

// ── filter ────────────────────────────────────────────────────────────────────
func (t fimTab) applyAgentFilter() fimTab {
	if t.searchInput == "" {
		t.agentsFilt = t.agents
		return t
	}
	q := strings.ToLower(t.searchInput)
	t.agentsFilt = t.agentsFilt[:0]
	for _, a := range t.agents {
		if strings.Contains(strings.ToLower(a.Name), q) ||
			strings.Contains(a.ID, q) {
			t.agentsFilt = append(t.agentsFilt, a)
		}
	}
	return t
}

func (t fimTab) applyEventFilter(files []api.SyscheckFile, idx int) []api.SyscheckFile {
	filter := fimEventFilters[idx]
	if filter == "all" {
		return files
	}
	out := make([]api.SyscheckFile, 0, len(files))
	for _, f := range files {
		if strings.EqualFold(f.Event, filter) {
			out = append(out, f)
		}
	}
	return out
}

// ── update ────────────────────────────────────────────────────────────────────
func (t fimTab) update(msg tea.Msg, width, height int) (fimTab, *modalModel, tea.Cmd) {
	switch msg := msg.(type) {

	case fimAgentsDataMsg:
		t.agentsLoading = false
		t.agentsLoaded = true
		t.agents = msg.agents
		t.agentsFilt = msg.agents
		t.cursor = 0
		t.offset = 0

	case fimEventsDataMsg:
		t.eventsLoading = false
		t.allFiles = msg.files
		t.total = msg.total
		t.files = t.applyEventFilter(t.allFiles, t.filterIdx)
		t.cursor = 0
		t.offset = 0

	case tea.KeyMsg:
		switch t.state {
		case fimViewAgents:
			return t.updateAgentList(msg, width, height)
		case fimViewEvents:
			return t.updateEventList(msg, width, height)
		}
	}
	return t, nil, nil
}

func (t fimTab) updateAgentList(msg tea.KeyMsg, _, height int) (fimTab, *modalModel, tea.Cmd) {
	listH := height - 6
	if listH < 1 {
		listH = 1
	}
	switch {
	case t.searchMode:
		switch msg.String() {
		case "esc", "enter":
			t.searchMode = false
		case "backspace":
			if len(t.searchInput) > 0 {
				t.searchInput = t.searchInput[:len(t.searchInput)-1]
			}
			t = t.applyAgentFilter()
			t.cursor = 0
			t.offset = 0
		default:
			if len(msg.Runes) > 0 {
				t.searchInput += string(msg.Runes)
				t = t.applyAgentFilter()
				t.cursor = 0
				t.offset = 0
			}
		}
	default:
		switch msg.String() {
		case "r":
			t.agentsLoading = true
			return t, nil, fimLoadAgents()
		case "/":
			t.searchMode = true
		case "esc":
			t.searchInput = ""
			t = t.applyAgentFilter()
		case "up", "k":
			if t.cursor > 0 {
				t.cursor--
				if t.cursor < t.offset {
					t.offset--
				}
			}
		case "down", "j":
			if t.cursor < len(t.agentsFilt)-1 {
				t.cursor++
				if t.cursor >= t.offset+listH {
					t.offset++
				}
			}
		case "enter":
			if len(t.agentsFilt) > 0 && t.cursor < len(t.agentsFilt) {
				a := t.agentsFilt[t.cursor]
				t.selectedAgent = &a
				t.state = fimViewEvents
				t.eventsLoading = true
				t.filterIdx = 0
				t.cursor = 0
				t.offset = 0
				return t, nil, fimLoadEvents(a.ID)
			}
		}
	}
	return t, nil, nil
}

func (t fimTab) updateEventList(msg tea.KeyMsg, _, height int) (fimTab, *modalModel, tea.Cmd) {
	listH := height - 7
	if listH < 1 {
		listH = 1
	}
	switch msg.String() {
	case "esc", "backspace":
		t.state = fimViewAgents
		t.allFiles = nil
		t.files = nil
		t.cursor = 0
		t.offset = 0
	case "f":
		t.filterIdx = (t.filterIdx + 1) % len(fimEventFilters)
		t.files = t.applyEventFilter(t.allFiles, t.filterIdx)
		t.cursor = 0
		t.offset = 0
	case "r":
		if t.selectedAgent != nil {
			t.eventsLoading = true
			return t, nil, fimLoadEvents(t.selectedAgent.ID)
		}
	case "up", "k":
		if t.cursor > 0 {
			t.cursor--
			if t.cursor < t.offset {
				t.offset--
			}
		}
	case "down", "j":
		if t.cursor < len(t.files)-1 {
			t.cursor++
			if t.cursor >= t.offset+listH {
				t.offset++
			}
		}
	case "enter":
		if len(t.files) > 0 && t.cursor < len(t.files) {
			f := t.files[t.cursor]
			lines := []string{
				fmt.Sprintf("File:        %s", f.File),
				fmt.Sprintf("Event:       %s", f.Event),
				fmt.Sprintf("Type:        %s", f.Type),
				"",
				fmt.Sprintf("Size:        %d bytes", f.Size),
				fmt.Sprintf("Permissions: %s", f.Perm),
				fmt.Sprintf("Owner:       %s / %s", f.Uname, f.Gname),
				fmt.Sprintf("Modified:    %s", f.Mtime),
				fmt.Sprintf("Detected:    %s", f.Date),
				"",
				fmt.Sprintf("MD5:         %s", f.Md5),
				fmt.Sprintf("SHA1:        %s", f.Sha1),
				fmt.Sprintf("SHA256:      %s", f.Sha256),
			}
			return t, &modalModel{title: "FIM Event Detail", lines: lines}, nil
		}
	}
	return t, nil, nil
}

// ── view ──────────────────────────────────────────────────────────────────────
func (t fimTab) view(width, height, spinFrame int) string {
	switch t.state {
	case fimViewAgents:
		return t.viewAgents(width, height, spinFrame)
	case fimViewEvents:
		return t.viewEvents(width, height, spinFrame)
	}
	return ""
}

func (t fimTab) viewAgents(width, height, spinFrame int) string {
	if t.agentsLoading || !t.agentsLoaded {
		return renderLoading(width, height, spinFrame)
	}

	var sb strings.Builder

	// Header row
	hStyle := lipgloss.NewStyle().Bold(true).Foreground(clrPrimary)
	sb.WriteString(fmt.Sprintf("  %-6s  %-22s  %-14s  %s\n",
		hStyle.Render("ID"), hStyle.Render("NAME"), hStyle.Render("IP"), hStyle.Render("OS")))
	sb.WriteString("  " + dDimStyle.Render(strings.Repeat("─", width-4)) + "\n")

	// Search bar
	searchBar := ""
	if t.searchMode {
		searchBar = lipgloss.NewStyle().Foreground(clrPrimary).Render("/") + t.searchInput + "█"
	} else if t.searchInput != "" {
		searchBar = dDimStyle.Render("filter: ") + t.searchInput
	}
	if searchBar != "" {
		sb.WriteString("  " + searchBar + "\n")
	}

	listH := height - 4
	if searchBar != "" {
		listH--
	}
	if listH < 1 {
		listH = 1
	}

	if len(t.agentsFilt) == 0 {
		sb.WriteString(lipgloss.Place(width, listH, lipgloss.Center, lipgloss.Center,
			dDimStyle.Render("no active agents")))
		return sb.String()
	}

	end := t.offset + listH
	if end > len(t.agentsFilt) {
		end = len(t.agentsFilt)
	}
	for i, a := range t.agentsFilt[t.offset:end] {
		abs := t.offset + i
		id := output.Truncate(a.ID, 6)
		name := output.Truncate(a.Name, 22)
		ip := output.Truncate(a.IP, 14)
		osStr := output.Truncate(a.Os.Name+" "+a.Os.Version, 24)
		line := fmt.Sprintf("  %-6s  %-22s  %-14s  %s", id, name, ip, osStr)
		if abs == t.cursor {
			sb.WriteString(dSelStyle.Width(width).Render(line) + "\n")
		} else {
			sb.WriteString(line + "\n")
		}
	}

	total := fmt.Sprintf("  %s active agents", dBrightStyle.Render(dashFmt(len(t.agentsFilt))))
	sb.WriteString("\n" + dDimStyle.Render(total))
	return sb.String()
}

func (t fimTab) viewEvents(width, height, spinFrame int) string {
	if t.eventsLoading {
		return renderLoading(width, height, spinFrame)
	}

	agentName := ""
	if t.selectedAgent != nil {
		agentName = t.selectedAgent.Name + " (" + t.selectedAgent.ID + ")"
	}

	var sb strings.Builder

	// Title bar
	filterLabel := fimEventFilters[t.filterIdx]
	filterStyle := dDimStyle
	switch filterLabel {
	case "added":
		filterStyle = dSuccessStyle
	case "modified":
		filterStyle = dWarnStyle
	case "deleted":
		filterStyle = dDangerStyle
	}
	sb.WriteString(fmt.Sprintf("  %s  %s  %s\n",
		dTitleStyle.Render(agentName),
		dDimStyle.Render("filter:"),
		filterStyle.Render("["+filterLabel+"]"),
	))
	shown := len(t.files)
	if fimEventFilters[t.filterIdx] == "all" {
		sb.WriteString(fmt.Sprintf("  %s events\n", dBrightStyle.Render(dashFmt(t.total))))
	} else {
		sb.WriteString(fmt.Sprintf("  %s / %s events\n",
			dBrightStyle.Render(dashFmt(shown)),
			dDimStyle.Render(dashFmt(t.total))))
	}
	sb.WriteString("  " + dDimStyle.Render(strings.Repeat("─", width-4)) + "\n")

	// Column headers
	hStyle := lipgloss.NewStyle().Bold(true).Foreground(clrPrimary)
	pathW := width - 32
	if pathW < 20 {
		pathW = 20
	}
	sb.WriteString(fmt.Sprintf("  %-10s  %-*s  %s\n",
		hStyle.Render("EVENT"),
		pathW, hStyle.Render("FILE"),
		hStyle.Render("DETECTED")))
	sb.WriteString("  " + dDimStyle.Render(strings.Repeat("─", width-4)) + "\n")

	listH := height - 7
	if listH < 1 {
		listH = 1
	}

	if len(t.files) == 0 {
		sb.WriteString(lipgloss.Place(width, listH, lipgloss.Center, lipgloss.Center,
			dDimStyle.Render("no FIM events")))
		return sb.String()
	}

	end := t.offset + listH
	if end > len(t.files) {
		end = len(t.files)
	}
	for i, f := range t.files[t.offset:end] {
		abs := t.offset + i
		evStr := output.Truncate(f.Event, 10)
		var evStyled string
		switch strings.ToLower(f.Event) {
		case "added":
			evStyled = dSuccessStyle.Render(fmt.Sprintf("%-10s", evStr))
		case "modified":
			evStyled = dWarnStyle.Render(fmt.Sprintf("%-10s", evStr))
		case "deleted":
			evStyled = dDangerStyle.Render(fmt.Sprintf("%-10s", evStr))
		default:
			evStyled = dDimStyle.Render(fmt.Sprintf("%-10s", evStr))
		}
		date := f.Date
		if date == "" {
			date = f.Mtime
		}
		if len(date) > 19 {
			date = date[:19]
		}
		filePath := output.Truncate(f.File, pathW)
		line := fmt.Sprintf("  %s  %-*s  %s",
			evStyled, pathW, filePath, dDimStyle.Render(date))
		if abs == t.cursor {
			sb.WriteString(dSelStyle.Width(width).Render(
				fmt.Sprintf("  %-10s  %-*s  %s", evStr, pathW, f.File, date)) + "\n")
		} else {
			sb.WriteString(line + "\n")
		}
	}
	return sb.String()
}
