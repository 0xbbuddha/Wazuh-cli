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
type overviewDataMsg struct {
	agentSummary *api.AgentSummary
	alertCounts  []int
	alertTotal   int
	recentAlerts []api.Alert
	vulnCounts   map[string]int
	vulnTotal    int
	loadedAt     time.Time
}

// ── tab ───────────────────────────────────────────────────────────────────────
type overviewTab struct {
	data        *overviewDataMsg
	loading     bool
	loadedAt    time.Time
	refreshSecs int
}

func newOverviewTab(refreshSecs int) overviewTab {
	return overviewTab{loading: true, refreshSecs: refreshSecs}
}

func (t overviewTab) init() tea.Cmd {
	return overviewLoad()
}

func overviewLoad() tea.Cmd {
	return func() tea.Msg {
		msg := overviewDataMsg{loadedAt: time.Now()}
		agAPI := api.NewAgentsAPI(managerClient)
		if s, err := agAPI.Summary(); err == nil {
			msg.agentSummary = s
		}
		if indexerClient != nil {
			if counts, err := indexerClient.AlertsHourly("", 24); err == nil {
				msg.alertCounts = counts
			}
			if alerts, total, err := indexerClient.Alerts(8, 0, ""); err == nil {
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

func (t overviewTab) update(msg tea.Msg, _, _ int) (overviewTab, *modalModel, tea.Cmd) {
	switch msg := msg.(type) {
	case overviewDataMsg:
		t.loading = false
		t.loadedAt = msg.loadedAt
		t.data = &msg
	case tea.KeyMsg:
		if msg.String() == "r" {
			t.loading = true
			return t, nil, overviewLoad()
		}
	case dashTickMsg:
		if t.refreshSecs > 0 && !t.loadedAt.IsZero() &&
			time.Since(t.loadedAt) >= time.Duration(t.refreshSecs)*time.Second {
			t.loading = true
			return t, nil, overviewLoad()
		}
	}
	return t, nil, nil
}

func (t overviewTab) view(width, height, spinFrame int) string {
	if t.loading || t.data == nil {
		return renderLoading(width, height, spinFrame)
	}

	d := t.data
	var parts []string

	if width >= 80 {
		parts = append(parts, t.renderCards(width, d))
	}

	colW := width/2 - 2
	textW := colW - 4

	left := lipgloss.JoinVertical(lipgloss.Left,
		t.renderAgentsPanel(colW, textW, d),
		t.renderRecentAlertsPanel(colW, textW, d),
	)
	right := lipgloss.JoinVertical(lipgloss.Left,
		t.renderAlertTrendPanel(colW, textW, d),
		t.renderVulnPanel(colW, textW, d),
	)
	parts = append(parts, lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right))

	return strings.Join(parts, "\n")
}

// ── cards ─────────────────────────────────────────────────────────────────────
func (t overviewTab) renderCards(width int, d *overviewDataMsg) string {
	total24h := 0
	for _, c := range d.alertCounts {
		total24h += c
	}
	var active, disconn, total int
	if d.agentSummary != nil {
		active = d.agentSummary.Connection.Active
		disconn = d.agentSummary.Connection.Disconnected
		total = d.agentSummary.Connection.Total
	}
	crit := d.vulnCounts["critical"]

	activeBorder := clrBorder
	if disconn > 0 {
		activeBorder = clrWarn
	}
	critBorder := clrBorder
	if crit > 0 {
		critBorder = clrDanger
	}

	cw := width/4 - 3
	if cw < 14 {
		cw = 14
	}
	c1 := metricCard(cw, "ACTIVE AGENTS", dashFmt(active), "online", activeBorder, clrSuccess)
	c2 := metricCard(cw, "ALERTS 24H", dashFmt(total24h), "events", clrBorder, clrWarn)
	c3 := metricCard(cw, "CRITICAL VULNS", dashFmt(crit), "CVEs", critBorder, clrDanger)
	var c4 string
	if disconn > 0 {
		c4 = metricCard(cw, "DISCONNECTED", dashFmt(disconn), "agents down", clrDanger, clrDanger)
	} else {
		c4 = metricCard(cw, "TOTAL AGENTS", dashFmt(total), "registered", clrBorder, clrBright)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, c1, "  ", c2, "  ", c3, "  ", c4)
}

func metricCard(width int, label, value, unit string, border, valColor lipgloss.Color) string {
	inner := width - 4
	if inner < 8 {
		inner = 8
	}
	top := dDimStyle.Width(inner).Align(lipgloss.Center).Render(label)
	mid := lipgloss.NewStyle().Bold(true).Foreground(valColor).Width(inner).Align(lipgloss.Center).Render(value)
	bot := dDimStyle.Width(inner).Align(lipgloss.Center).Render(unit)
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(border).
		Width(width).Padding(0, 1).
		Render(top + "\n" + mid + "\n" + bot)
}

// ── panels ────────────────────────────────────────────────────────────────────
func (t overviewTab) renderAgentsPanel(colW, textW int, d *overviewDataMsg) string {
	var sb strings.Builder
	sb.WriteString(dTitleStyle.Render("AGENTS") + "\n\n")
	if d.agentSummary == nil {
		sb.WriteString(dDimStyle.Render("unavailable"))
	} else {
		s := d.agentSummary.Connection
		type row struct {
			bullet string
			style  lipgloss.Style
			label  string
			count  int
		}
		for _, r := range []row{
			{"●", dSuccessStyle, "Active", s.Active},
			{"○", dDangerStyle, "Disconnected", s.Disconnected},
			{"◌", dWarnStyle, "Pending", s.Pending},
			{"·", dDimStyle, "Never connected", s.NeverConnected},
		} {
			sb.WriteString(fmt.Sprintf("  %s  %-18s %s\n",
				r.style.Render(r.bullet), r.label,
				dBrightStyle.Render(dashFmt(r.count))))
		}
		sb.WriteString("\n  " + dDimStyle.Render(strings.Repeat("─", textW)) + "\n\n")
		c := d.agentSummary.Config
		pct := 0
		if c.Total > 0 {
			pct = c.Synced * 100 / c.Total
		}
		syncStyle := dSuccessStyle
		if pct < 80 {
			syncStyle = dWarnStyle
		}
		if pct < 50 {
			syncStyle = dDangerStyle
		}
		sb.WriteString(fmt.Sprintf("  %-18s %s\n", "Config sync:",
			syncStyle.Render(fmt.Sprintf("%d%%", pct))))
	}
	return dPanelStyle.Width(colW).Render(sb.String())
}

func (t overviewTab) renderAlertTrendPanel(colW, textW int, d *overviewDataMsg) string {
	var sb strings.Builder
	if indexerClient == nil {
		sb.WriteString(dTitleStyle.Render("SECURITY EVENTS") + "\n\n")
		sb.WriteString(dDimStyle.Render("Configure [indexer] in config.toml"))
		return dPanelStyle.Width(colW).Render(sb.String())
	}
	total := 0
	for _, c := range d.alertCounts {
		total += c
	}
	sb.WriteString(dTitleStyle.Render("SECURITY EVENTS") + "  " +
		dDimStyle.Render(fmt.Sprintf("24h · %s events", dashFmt(total))) + "\n\n")
	if len(d.alertCounts) == 0 {
		sb.WriteString(dDimStyle.Render("no data"))
	} else {
		counts := d.alertCounts
		if len(counts) > textW {
			counts = counts[len(counts)-textW:]
		}
		spark := lipgloss.NewStyle().Foreground(clrWarn).Render(output.Sparkline(counts))
		sb.WriteString("  " + spark + "\n\n")
		nH := len(counts)
		left := fmt.Sprintf("%dh ago", nH)
		spaces := textW - len(left) - 3
		if spaces < 1 {
			spaces = 1
		}
		sb.WriteString("  " + dDimStyle.Render(left+strings.Repeat(" ", spaces)+"now"))
	}
	return dPanelStyle.Width(colW).Render(sb.String())
}

func (t overviewTab) renderRecentAlertsPanel(colW, textW int, d *overviewDataMsg) string {
	var sb strings.Builder
	total := ""
	if indexerClient != nil {
		total = "  " + dDimStyle.Render(dashFmt(d.alertTotal)+" total")
	}
	sb.WriteString(dTitleStyle.Render("RECENT ALERTS") + total + "\n\n")
	if indexerClient == nil {
		sb.WriteString(dDimStyle.Render("Configure [indexer] in config.toml"))
	} else if len(d.recentAlerts) == 0 {
		sb.WriteString(dDimStyle.Render("no recent alerts"))
	} else {
		maxDesc := textW - 20
		if maxDesc < 10 {
			maxDesc = 10
		}
		for _, a := range d.recentAlerts {
			lvl := output.ColorLevel(a.Rule.Level)
			agent := output.Truncate(a.Agent.Name, 12)
			desc := output.Truncate(a.Rule.Description, maxDesc)
			sb.WriteString(fmt.Sprintf("  %s  %-14s %s\n", lvl, agent, desc))
		}
	}
	return dPanelStyle.Width(colW).Render(strings.TrimRight(sb.String(), "\n"))
}

func (t overviewTab) renderVulnPanel(colW, textW int, d *overviewDataMsg) string {
	var sb strings.Builder
	sb.WriteString(dTitleStyle.Render("VULNERABILITIES") + "\n\n")
	if indexerClient == nil {
		sb.WriteString(dDimStyle.Render("Configure [indexer] in config.toml"))
	} else if d.vulnCounts == nil {
		sb.WriteString(dDimStyle.Render("unavailable"))
	} else {
		maxCount := 1
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if v := d.vulnCounts[sev]; v > maxCount {
				maxCount = v
			}
		}
		barMaxW := textW - 16
		if barMaxW < 4 {
			barMaxW = 4
		}
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			count := d.vulnCounts[sev]
			st := dSevStyles[sev]
			barLen := 0
			if maxCount > 0 && count > 0 {
				barLen = count*barMaxW/maxCount + 1
				if barLen > barMaxW {
					barLen = barMaxW
				}
			}
			bar := st.Render(strings.Repeat("█", barLen))
			pad := strings.Repeat(" ", barMaxW-barLen)
			sb.WriteString(fmt.Sprintf("  %s %s%s %s\n",
				st.Render(fmt.Sprintf("%-8s", strings.ToUpper(sev))),
				bar, pad,
				dDimStyle.Render(fmt.Sprintf("%6d", count))))
		}
		sb.WriteString(fmt.Sprintf("\n  %-9s %s", "Total:", dBrightStyle.Render(dashFmt(d.vulnTotal))))
	}
	return dPanelStyle.Width(colW).Render(sb.String())
}
