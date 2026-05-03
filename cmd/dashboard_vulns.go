package cmd

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

// ── data message ──────────────────────────────────────────────────────────────
type vulnsDataMsg struct {
	vulns  []api.IndexerVulnerability
	total  int
	counts map[string]int
	sev    string
}

// ── severity filter cycle ─────────────────────────────────────────────────────
var (
	vulnsSevFilters = []string{"", "critical", "high", "medium", "low"}
	vulnsSevLabels  = []string{"ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"}
	vulnsSevIdx     = 0
)

// ── tab ───────────────────────────────────────────────────────────────────────
type vulnsTab struct {
	vulns     []api.IndexerVulnerability
	total     int
	counts    map[string]int
	cursor    int
	offset    int
	loading   bool
	loaded    bool
	sevFilter string
}

func newVulnsTab() vulnsTab { return vulnsTab{} }

func vulnsLoad(t vulnsTab) tea.Cmd {
	sev := t.sevFilter
	return func() tea.Msg {
		if indexerClient == nil {
			return vulnsDataMsg{sev: sev}
		}
		counts, _, _ := indexerClient.VulnsBySeverity()
		vulns, total, err := indexerClient.Vulnerabilities("", sev, 300)
		if err != nil {
			vulns = nil
		}
		return vulnsDataMsg{vulns: vulns, total: total, counts: counts, sev: sev}
	}
}

func (t vulnsTab) update(msg tea.Msg, _, height int) (vulnsTab, *modalModel, tea.Cmd) {
	visH := height - 6
	if visH < 1 {
		visH = 1
	}

	switch msg := msg.(type) {
	case vulnsDataMsg:
		t.loading = false
		t.loaded = true
		t.vulns = msg.vulns
		t.total = msg.total
		t.counts = msg.counts
		t.sevFilter = msg.sev
		if t.cursor >= len(t.vulns) {
			t.cursor = max(0, len(t.vulns)-1)
		}
		return t, nil, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			if t.cursor < len(t.vulns)-1 {
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
			t.cursor = max(0, len(t.vulns)-1)
			t.offset = max(0, t.cursor-visH+1)
		case "f":
			vulnsSevIdx = (vulnsSevIdx + 1) % len(vulnsSevFilters)
			t.sevFilter = vulnsSevFilters[vulnsSevIdx]
			t.loading, t.cursor, t.offset = true, 0, 0
			return t, nil, vulnsLoad(t)
		case "r":
			t.loading, t.cursor, t.offset = true, 0, 0
			return t, nil, vulnsLoad(t)
		case "enter":
			if t.cursor < len(t.vulns) {
				return t, vulnDetailModal(t.vulns[t.cursor]), nil
			}
		}
	}
	return t, nil, nil
}

// ── view ──────────────────────────────────────────────────────────────────────
func (t vulnsTab) view(width, height, spinFrame int) string {
	var sb strings.Builder
	sb.WriteString(t.renderSummaryBar() + "\n")
	sb.WriteString(t.renderFilterBar() + "\n")

	if indexerClient == nil {
		sb.WriteString("\n  " + dDimStyle.Render("Configure [indexer] in config.toml to view vulnerabilities"))
		return sb.String()
	}
	if t.loading {
		sb.WriteString(renderLoading(width, height-3, spinFrame))
		return sb.String()
	}

	colHdr := fmt.Sprintf("  %-18s %-10s %-6s %-20s %-14s %s",
		"CVE", "SEVERITY", "SCORE", "PACKAGE", "VERSION", "AGENT")
	sb.WriteString(dDimStyle.Render(colHdr) + "\n")
	sb.WriteString(dDimStyle.Render("  "+strings.Repeat("─", width-4)) + "\n")

	if len(t.vulns) == 0 {
		sb.WriteString("\n  " + dDimStyle.Render("No vulnerabilities found"))
		return sb.String()
	}

	visH := height - 6
	if visH < 1 {
		visH = 1
	}

	for i := t.offset; i < t.offset+visH && i < len(t.vulns); i++ {
		v := t.vulns[i]
		sev := strings.ToLower(v.Vuln.Severity)
		st, ok := dSevStyles[sev]
		if !ok {
			st = dDimStyle
		}
		score := fmt.Sprintf("%.1f", v.Vuln.Score.Base)
		cve := output.Truncate(v.Vuln.ID, 16)
		pkg := output.Truncate(v.Package.Name, 18)
		ver := output.Truncate(v.Package.Version, 12)
		agent := output.Truncate(v.Agent.Name, 14)
		line := fmt.Sprintf("  %-18s %s %-6s %-20s %-14s %s",
			cve,
			st.Render(fmt.Sprintf("%-10s", strings.ToUpper(sev))),
			score, pkg, ver, agent)
		if i == t.cursor {
			line = dSelStyle.Width(width).Render(line)
		}
		sb.WriteString(line + "\n")
	}

	sb.WriteString(dDimStyle.Render(fmt.Sprintf("  %d/%s  cursor:%d",
		min(len(t.vulns), visH+t.offset), dashFmt(t.total), t.cursor+1)))
	return sb.String()
}

func (t vulnsTab) renderSummaryBar() string {
	if t.counts == nil {
		return dDimStyle.Render("  No data")
	}
	var parts []string
	parts = append(parts, "  ")
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		st := dSevStyles[sev]
		label := strings.ToUpper(sev)
		if len(label) > 4 {
			label = label[:4]
		}
		parts = append(parts,
			st.Render(label)+
				dDimStyle.Render(fmt.Sprintf(":%d  ", t.counts[sev])))
	}
	return strings.Join(parts, "")
}

func (t vulnsTab) renderFilterBar() string {
	var parts []string
	parts = append(parts, dDimStyle.Render("  Severity: "))
	for i, label := range vulnsSevLabels {
		if vulnsSevFilters[i] == t.sevFilter {
			parts = append(parts, lipgloss.NewStyle().Bold(true).Foreground(clrPrimary).
				Background(lipgloss.Color("236")).Padding(0, 1).Render(label))
		} else {
			parts = append(parts, dDimStyle.Render(" "+label+" "))
		}
	}
	parts = append(parts, dDimStyle.Render(fmt.Sprintf("   %s total  (f to cycle)", dashFmt(t.total))))
	return strings.Join(parts, "")
}

// ── vuln detail modal ─────────────────────────────────────────────────────────
func vulnDetailModal(v api.IndexerVulnerability) *modalModel {
	var lines []string
	add := func(k, val string) { lines = append(lines, fmt.Sprintf("%-18s %s", k+":", val)) }
	add("CVE", v.Vuln.ID)
	add("Severity", v.Vuln.Severity)
	add("CVSS Score", fmt.Sprintf("%.1f", v.Vuln.Score.Base))
	lines = append(lines, "")
	add("Package", v.Package.Name)
	add("Version", v.Package.Version)
	add("Architecture", v.Package.Architecture)
	lines = append(lines, "")
	add("Agent", fmt.Sprintf("%s (%s)", v.Agent.Name, v.Agent.ID))
	add("Published", v.Vuln.Published)

	if v.Vuln.Description != "" {
		lines = append(lines, "", "Description:")
		// Word-wrap at 68 chars
		words := strings.Fields(v.Vuln.Description)
		line := "  "
		for _, w := range words {
			if len(line)+len(w)+1 > 70 {
				lines = append(lines, line)
				line = "  " + w
			} else if line == "  " {
				line += w
			} else {
				line += " " + w
			}
		}
		if line != "  " {
			lines = append(lines, line)
		}
	}

	return &modalModel{title: v.Vuln.ID, lines: lines}
}
