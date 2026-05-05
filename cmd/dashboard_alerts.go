package cmd

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

// ── data message ──────────────────────────────────────────────────────────────
type discoverDataMsg struct {
	alerts []api.Alert
	total  int
	query  string
	level  int
}

// ── level filter cycle ────────────────────────────────────────────────────────
var (
	discoverLevels = []int{0, 5, 8, 10, 12}
	discoverLabels = []string{"ALL", "5+", "8+", "10+", "12+"}
	discoverLvlIdx = 0
)

// ── tab ───────────────────────────────────────────────────────────────────────
type discoverTab struct {
	alerts      []api.Alert
	total       int
	cursor      int
	offset      int
	loading     bool
	loaded      bool
	searchMode  bool
	searchInput string
	levelFilter int
}

func newDiscoverTab() discoverTab { return discoverTab{} }

func discoverLoad(t discoverTab) tea.Cmd {
	q, lvl := t.searchInput, t.levelFilter
	return func() tea.Msg {
		if indexerClient == nil {
			return discoverDataMsg{query: q, level: lvl}
		}
		var alerts []api.Alert
		var total int
		var err error
		if q != "" {
			alerts, total, err = indexerClient.AlertsFiltered(q, lvl, "", 200)
		} else {
			alerts, total, err = indexerClient.Alerts(200, lvl, "")
		}
		if err != nil {
			return discoverDataMsg{query: q, level: lvl}
		}
		return discoverDataMsg{alerts: alerts, total: total, query: q, level: lvl}
	}
}

func (t discoverTab) update(msg tea.Msg, _, height int) (discoverTab, *modalModel, tea.Cmd) {
	visH := height - 6
	if visH < 1 {
		visH = 1
	}

	switch msg := msg.(type) {
	case discoverDataMsg:
		t.loading = false
		t.loaded = true
		t.alerts = msg.alerts
		t.total = msg.total
		t.levelFilter = msg.level
		if t.cursor >= len(t.alerts) {
			t.cursor = max(0, len(t.alerts)-1)
		}
		return t, nil, nil

	case tea.KeyMsg:
		if t.searchMode {
			return t.handleSearchKey(msg)
		}
		switch msg.String() {
		case "j", "down":
			if t.cursor < len(t.alerts)-1 {
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
			t.cursor = max(0, len(t.alerts)-1)
			t.offset = max(0, t.cursor-visH+1)
		case "f":
			discoverLvlIdx = (discoverLvlIdx + 1) % len(discoverLevels)
			t.levelFilter = discoverLevels[discoverLvlIdx]
			t.loading, t.cursor, t.offset = true, 0, 0
			return t, nil, discoverLoad(t)
		case "r":
			t.loading, t.cursor, t.offset = true, 0, 0
			return t, nil, discoverLoad(t)
		case "/":
			t.searchMode = true
		case "esc":
			if t.searchInput != "" {
				t.searchInput = ""
				t.loading, t.cursor, t.offset = true, 0, 0
				return t, nil, discoverLoad(t)
			}
		case "enter":
			if t.cursor < len(t.alerts) {
				return t, alertDetailModal(t.alerts[t.cursor]), nil
			}
		}
	}
	return t, nil, nil
}

func (t discoverTab) handleSearchKey(msg tea.KeyMsg) (discoverTab, *modalModel, tea.Cmd) {
	switch msg.String() {
	case "enter":
		t.searchMode = false
		t.loading, t.cursor, t.offset = true, 0, 0
		return t, nil, discoverLoad(t)
	case "esc":
		t.searchMode = false
	case "backspace", "ctrl+h":
		if len(t.searchInput) > 0 {
			t.searchInput = t.searchInput[:len(t.searchInput)-1]
		}
	case "ctrl+u":
		t.searchInput = ""
	default:
		if len(msg.Runes) > 0 {
			t.searchInput += string(msg.Runes)
		}
	}
	return t, nil, nil
}

// ── view ──────────────────────────────────────────────────────────────────────
func (t discoverTab) view(width, height, spinFrame int) string {
	var sb strings.Builder
	sb.WriteString(t.renderSearchBar(width) + "\n")
	sb.WriteString(t.renderFilterBar() + "\n")

	if indexerClient == nil {
		sb.WriteString("\n  " + dDimStyle.Render("Configure [indexer] in config.toml to use Discover"))
		return sb.String()
	}
	if t.loading {
		sb.WriteString(renderLoading(width, height-3, spinFrame))
		return sb.String()
	}

	colHdr := fmt.Sprintf("  %-14s %-4s %-16s %s", "TIME", "LVL", "AGENT", "DESCRIPTION")
	sb.WriteString(dDimStyle.Render(colHdr) + "\n")
	sb.WriteString(dDimStyle.Render("  "+strings.Repeat("─", width-4)) + "\n")

	if len(t.alerts) == 0 {
		sb.WriteString("\n  " + dDimStyle.Render("No alerts found"))
		return sb.String()
	}

	visH := height - 6
	if visH < 1 {
		visH = 1
	}
	descW := width - 14 - 6 - 18 - 4
	if descW < 10 {
		descW = 10
	}

	for i := t.offset; i < t.offset+visH && i < len(t.alerts); i++ {
		a := t.alerts[i]
		ts := fmtAlertTime(a.Timestamp)
		lvl := output.ColorLevel(a.Rule.Level)
		agent := output.Truncate(a.Agent.Name, 14)
		desc := output.Truncate(a.Rule.Description, descW)
		line := fmt.Sprintf("  %-14s %s  %-16s %s", ts, lvl, agent, desc)
		if i == t.cursor {
			line = dSelStyle.Width(width).Render(line)
		}
		sb.WriteString(line + "\n")
	}

	pct := ""
	if t.total > 0 {
		pct = fmt.Sprintf("  %d/%s", min(len(t.alerts), visH+t.offset), dashFmt(t.total))
	}
	sb.WriteString(dDimStyle.Render(pct + "  cursor:" + fmt.Sprintf("%d", t.cursor+1)))
	return sb.String()
}

func (t discoverTab) renderSearchBar(width int) string {
	prefix := dDimStyle.Render("  Search: ")
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
			dDimStyle.Render("  (/ to edit · Esc to clear)")
	}
	return prefix + dDimStyle.Render("press / to search")
}

func (t discoverTab) renderFilterBar() string {
	var parts []string
	parts = append(parts, dDimStyle.Render("  Level: "))
	for i, label := range discoverLabels {
		if discoverLevels[i] == t.levelFilter {
			parts = append(parts, lipgloss.NewStyle().Bold(true).Foreground(clrPrimary).
				Background(lipgloss.Color("236")).Padding(0, 1).Render(label))
		} else {
			parts = append(parts, dDimStyle.Render(" "+label+" "))
		}
	}
	if t.total > 0 {
		parts = append(parts, dDimStyle.Render(fmt.Sprintf("   %s total  (f to cycle)", dashFmt(t.total))))
	}
	return strings.Join(parts, "")
}

// ── alert detail modal ────────────────────────────────────────────────────────
func alertDetailModal(a api.Alert) *modalModel {
	var lines []string
	add := func(k, v string) { lines = append(lines, fmt.Sprintf("%-16s %s", k+":", v)) }
	add("Timestamp", a.Timestamp)
	add("Rule ID", a.Rule.ID)
	add("Level", fmt.Sprintf("%d", a.Rule.Level))
	add("Description", a.Rule.Description)
	add("Agent", fmt.Sprintf("%s (%s)", a.Agent.Name, a.Agent.ID))
	add("Agent IP", a.Agent.IP)
	add("Manager", a.Manager.Name)
	add("Location", a.Location)
	if len(a.Rule.Groups) > 0 {
		add("Groups", strings.Join(a.Rule.Groups, ", "))
	}
	if a.FullLog != "" {
		log := strings.TrimSpace(a.FullLog)
		if len(log) > 4096 {
			log = log[:4096] + "… [truncated]"
		}
		lines = append(lines, "", "Full log:")
		for _, part := range strings.Split(log, "\n") {
			lines = append(lines, "  "+part)
		}
	}
	return &modalModel{title: "Alert Detail", lines: lines}
}

// ── helpers ───────────────────────────────────────────────────────────────────
func fmtAlertTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		if len(ts) >= 19 {
			return ts[5:19] // drop year, keep MM-DDThh:mm:ss
		}
		return ts
	}
	return t.Format("01-02 15:04:05")
}
