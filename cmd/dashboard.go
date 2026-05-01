package cmd

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

// ---------- styles ----------

var (
	dashPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)

	dashTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("86"))

	dashDimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

	dashSevStyles = map[string]lipgloss.Style{
		"critical": lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true),
		"high":     lipgloss.NewStyle().Foreground(lipgloss.Color("196")),
		"medium":   lipgloss.NewStyle().Foreground(lipgloss.Color("214")),
		"low":      lipgloss.NewStyle().Foreground(lipgloss.Color("46")),
	}

	dashActiveStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	dashAlertStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
)

// ---------- messages ----------

type dashDataMsg struct {
	agentSummary *api.AgentSummary
	alertCounts  []int
	alertTotal   int
	recentAlerts []api.Alert
	vulnCounts   map[string]int
	vulnTotal    int
	loadedAt     time.Time
}

type dashTickMsg time.Time

// ---------- model ----------

var dashSpinChars = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type dashModel struct {
	width, height int
	refreshSecs   int
	loading       bool
	spinFrame     int
	loadedAt      time.Time
	data          *dashDataMsg
}

func newDashModel(refreshSecs int) dashModel {
	return dashModel{loading: true, refreshSecs: refreshSecs}
}

func (m dashModel) Init() tea.Cmd {
	return tea.Batch(dashLoad(), dashTick())
}

func dashLoad() tea.Cmd {
	return func() tea.Msg {
		msg := dashDataMsg{loadedAt: time.Now()}

		agAPI := api.NewAgentsAPI(managerClient)
		if s, err := agAPI.Summary(); err == nil {
			msg.agentSummary = s
		}

		if indexerClient != nil {
			if counts, err := indexerClient.AlertsHourly("", 24); err == nil {
				msg.alertCounts = counts
			}
			if alerts, total, err := indexerClient.Alerts(10, 0, ""); err == nil {
				msg.recentAlerts = alerts
				msg.alertTotal = total
			}
			if counts, total, err := indexerClient.VulnsBySeverity(); err == nil {
				msg.vulnCounts = counts
				msg.vulnTotal = total
			}
		}

		return msg
	}
}

func dashTick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return dashTickMsg(t)
	})
}

func (m dashModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "r":
			m.loading = true
			return m, dashLoad()
		}

	case dashDataMsg:
		m.loading = false
		m.loadedAt = msg.loadedAt
		m.data = &msg

	case dashTickMsg:
		m.spinFrame = (m.spinFrame + 1) % len(dashSpinChars)
		cmds := []tea.Cmd{dashTick()}
		if m.refreshSecs > 0 && !m.loadedAt.IsZero() &&
			time.Since(m.loadedAt) >= time.Duration(m.refreshSecs)*time.Second {
			m.loading = true
			cmds = append(cmds, dashLoad())
		}
		return m, tea.Batch(cmds...)
	}

	return m, nil
}

func (m dashModel) View() string {
	if m.width == 0 {
		return ""
	}

	statusStr := dashDimStyle.Render("q quit  r refresh")
	if m.loading {
		statusStr = dashSpinChars[m.spinFrame] + " loading..."
	} else if !m.loadedAt.IsZero() {
		statusStr = dashDimStyle.Render(fmt.Sprintf(
			"q quit  r refresh  %s  auto: %ds",
			m.loadedAt.Format("15:04:05"), m.refreshSecs))
	}
	header := dashTitleStyle.Render("WAZUH-CLI DASHBOARD") + "  " + statusStr

	if m.data == nil {
		return header + "\n\n" + dashDimStyle.Render("Loading...")
	}

	// Each panel has border (1+1) + padding (1+1) = 4 chars horizontal overhead.
	// Two columns + 2-char gap: 2*(colW) + 2 = m.width  →  colW = (m.width-2)/2
	colW := (m.width - 2) / 2
	if colW < 24 {
		colW = 24
	}
	// Inner text width available inside each panel.
	textW := colW - 4
	if textW < 10 {
		textW = 10
	}

	leftCol := lipgloss.JoinVertical(lipgloss.Left,
		m.renderAgentsPanel(colW, textW),
		m.renderVulnPanel(colW, textW),
	)
	rightCol := lipgloss.JoinVertical(lipgloss.Left,
		m.renderAlertTrendPanel(colW, textW),
		m.renderRecentAlertsPanel(colW, textW),
	)

	body := lipgloss.JoinHorizontal(lipgloss.Top, leftCol, "  ", rightCol)
	return header + "\n\n" + body
}

// ---------- panel renderers ----------

func (m dashModel) renderAgentsPanel(colW, textW int) string {
	var sb strings.Builder
	sb.WriteString(dashTitleStyle.Render("Agents") + "\n\n")

	if m.data.agentSummary == nil {
		sb.WriteString(dashDimStyle.Render("unavailable"))
	} else {
		s := m.data.agentSummary.Connection
		sb.WriteString(fmt.Sprintf("%-22s %s\n", "Active:",
			dashActiveStyle.Render(fmt.Sprintf("%d", s.Active))))
		sb.WriteString(fmt.Sprintf("%-22s %s\n", "Disconnected:",
			dashAlertStyle.Render(fmt.Sprintf("%d", s.Disconnected))))
		sb.WriteString(fmt.Sprintf("%-22s %d\n", "Pending:", s.Pending))
		sb.WriteString(fmt.Sprintf("%-22s %s\n", "Never connected:",
			dashDimStyle.Render(fmt.Sprintf("%d", s.NeverConnected))))
		sb.WriteString(fmt.Sprintf("%-22s %d", "Total:", s.Total))
	}

	return dashPanelStyle.Width(colW).Render(sb.String())
}

func (m dashModel) renderVulnPanel(colW, textW int) string {
	var sb strings.Builder
	sb.WriteString(dashTitleStyle.Render("Vulnerabilities") + "\n\n")

	if indexerClient == nil {
		sb.WriteString(dashDimStyle.Render("configure [indexer] in config.toml"))
	} else if m.data.vulnCounts == nil {
		sb.WriteString(dashDimStyle.Render("unavailable"))
	} else {
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			style := dashSevStyles[sev]
			count := m.data.vulnCounts[sev]
			sb.WriteString(fmt.Sprintf("%-12s %s\n",
				strings.ToUpper(sev)+":",
				style.Render(fmt.Sprintf("%d", count))))
		}
		sb.WriteString("\n")
		sb.WriteString(dashDimStyle.Render(fmt.Sprintf("Total: %d", m.data.vulnTotal)))
	}

	return dashPanelStyle.Width(colW).Render(sb.String())
}

func (m dashModel) renderAlertTrendPanel(colW, textW int) string {
	var sb strings.Builder
	sb.WriteString(dashTitleStyle.Render("Alert Trend (24h)") + "\n\n")

	if indexerClient == nil {
		sb.WriteString(dashDimStyle.Render("configure [indexer] in config.toml"))
	} else if len(m.data.alertCounts) == 0 {
		sb.WriteString(dashDimStyle.Render("no data"))
	} else {
		total := 0
		for _, c := range m.data.alertCounts {
			total += c
		}
		sb.WriteString(fmt.Sprintf("Total: %d alerts\n\n", total))

		counts := m.data.alertCounts
		if len(counts) > textW {
			counts = counts[len(counts)-textW:]
		}
		spark := output.Sparkline(counts)
		sb.WriteString(spark + "\n\n")

		nHours := len(counts)
		left := fmt.Sprintf("%dh ago", nHours)
		spaces := textW - len(left) - 3
		if spaces < 1 {
			spaces = 1
		}
		sb.WriteString(dashDimStyle.Render(left + strings.Repeat(" ", spaces) + "now"))
	}

	return dashPanelStyle.Width(colW).Render(sb.String())
}

func (m dashModel) renderRecentAlertsPanel(colW, textW int) string {
	title := fmt.Sprintf("Recent Alerts (%d total)", m.data.alertTotal)
	var sb strings.Builder
	sb.WriteString(dashTitleStyle.Render(title) + "\n\n")

	if indexerClient == nil {
		sb.WriteString(dashDimStyle.Render("configure [indexer] in config.toml"))
	} else if len(m.data.recentAlerts) == 0 {
		sb.WriteString(dashDimStyle.Render("no recent alerts"))
	} else {
		maxDescLen := textW - 20
		if maxDescLen < 10 {
			maxDescLen = 10
		}
		for i, a := range m.data.recentAlerts {
			desc := output.Truncate(a.Rule.Description, maxDescLen)
			agent := output.Truncate(a.Agent.Name, 12)
			line := fmt.Sprintf("%s %-14s %s", output.ColorLevel(a.Rule.Level), agent, desc)
			if i < len(m.data.recentAlerts)-1 {
				line += "\n"
			}
			sb.WriteString(line)
		}
	}

	return dashPanelStyle.Width(colW).Render(sb.String())
}

// ---------- command ----------

func newDashboardCmd() *cobra.Command {
	var refreshSecs int
	cmd := &cobra.Command{
		Use:     "dashboard",
		Short:   "Live TUI dashboard (agents, alerts, vulnerabilities)",
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
