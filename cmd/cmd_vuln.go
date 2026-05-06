package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleVuln(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"vuln"})
		return
	}
	switch args[0] {
	case "list":
		vulnList(args[1:])
	case "summary":
		vulnSummary(args[1:])
	default:
		printUnknownSub("vuln", args[0])
	}
}

func vulnList(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: vuln list <agent_id> [--severity S] [--limit N]"))
		return
	}
	fs := flag.NewFlagSet("vuln list", flag.ContinueOnError)
	severity := fs.String("severity", "", "Filter by severity: critical, high, medium, low")
	limit := fs.Int("limit", 500, "Maximum number of results")
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	v := api.NewVulnAPI(managerClient)
	vulns, total, err := v.List(agentID, *severity, *limit)
	if err != nil {
		if !isVulnNotFound(err) {
			printErr(err)
			return
		}
		if indexerClient == nil {
			fmt.Println(color.YellowString("[!]") + " vulnerability data not available via manager API (Wazuh 4.8+).")
			fmt.Println("Configure [indexer] in config.toml to query vulnerabilities from the indexer.")
			return
		}
		listVulnsFromIndexer(agentID, *severity, *limit)
		return
	}
	if output.Format == "json" {
		output.JSON(vulns)
		return
	}
	output.ShowCount(len(vulns), total, "vulnerabilities")
	t := output.NewTable("CVE", "SEVERITY", "PACKAGE", "VERSION", "TITLE")
	for _, vv := range vulns {
		title := vv.Title
		if len(title) > 60 {
			title = title[:57] + "..."
		}
		t.Row(vv.CVE, output.SeverityBadge(vv.Severity), vv.Name, vv.Version, title)
	}
	t.Flush()
}

func vulnSummary(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: vuln summary <agent_id> [--limit N]"))
		return
	}
	fs := flag.NewFlagSet("vuln summary", flag.ContinueOnError)
	limit := fs.Int("limit", 5000, "Max vulnerabilities to aggregate")
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	if indexerClient != nil {
		summarizeVulnsFromIndexer(agentID, *limit)
		return
	}
	v := api.NewVulnAPI(managerClient)
	summary, err := v.Summary(agentID, "severity")
	if err != nil {
		if isVulnNotFound(err) {
			printWarn("configure [indexer] in config.toml to query vulnerabilities (Wazuh 4.8+)")
			return
		}
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(summary)
		return
	}
	for k, val := range summary {
		fmt.Printf("%-12s %s\n", k+":", output.ColorSeverity(fmt.Sprintf("%v", val)))
	}
}

type vulnFlatJSON struct {
	CVE         string  `json:"cve"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
	Package     string  `json:"package"`
	Version     string  `json:"version"`
	Description string  `json:"description,omitempty"`
	Published   string  `json:"published,omitempty"`
	Agent       string  `json:"agent"`
	AgentID     string  `json:"agent_id"`
}

func listVulnsFromIndexer(agentID, severity string, limit int) {
	vulns, total, err := indexerClient.Vulnerabilities(agentID, severity, limit)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		flat := make([]vulnFlatJSON, len(vulns))
		for i, v := range vulns {
			flat[i] = vulnFlatJSON{
				CVE:         v.Vuln.ID,
				Severity:    strings.ToLower(v.Vuln.Severity),
				Score:       v.Vuln.Score.Base,
				Package:     v.Package.Name,
				Version:     v.Package.Version,
				Description: v.Vuln.Description,
				Published:   v.Vuln.Published,
				Agent:       v.Agent.Name,
				AgentID:     v.Agent.ID,
			}
		}
		output.JSON(flat)
		return
	}
	fmt.Printf("Showing %d of %d vulnerabilities (via indexer)\n\n", len(vulns), total)
	t := output.NewTable("CVE", "SEVERITY", "SCORE", "PACKAGE", "VERSION")
	for _, vv := range vulns {
		t.Row(vv.Vuln.ID, output.SeverityBadge(vv.Vuln.Severity),
			fmt.Sprintf("%.1f", vv.Vuln.Score.Base), vv.Package.Name, vv.Package.Version)
	}
	t.Flush()
}

func summarizeVulnsFromIndexer(agentID string, limit int) {
	vulns, total, err := indexerClient.Vulnerabilities(agentID, "", limit)
	if err != nil {
		printErr(err)
		return
	}
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
	for _, v := range vulns {
		sev := strings.ToLower(v.Vuln.Severity)
		if _, ok := counts[sev]; ok {
			counts[sev]++
		}
	}
	if output.Format == "json" {
		output.JSON(map[string]any{"total": total, "by_severity": counts})
		return
	}
	fmt.Printf("Total: %d vulnerabilities\n\n", total)
	for _, sev := range []string{"critical", "high", "medium", "low", "none"} {
		fmt.Printf("%-12s %s\n", sev+":", output.ColorSeverity(fmt.Sprintf("%d", counts[sev])))
	}
}

func isVulnNotFound(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "404") || strings.Contains(msg, "Not Found")
}
