package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newVulnCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "vuln",
		Short:   "Vulnerability detection results",
		Aliases: []string{"v"},
	}

	var (
		severity string
		limit    int
	)
	listCmd := &cobra.Command{
		Use:   "list <agent_id>",
		Short: "List detected vulnerabilities for an agent",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			v := api.NewVulnAPI(managerClient)
			vulns, total, err := v.List(args[0], severity, limit)
			if err != nil {
				if !isVulnNotFound(err) {
					die(err)
				}
				// Wazuh 4.8+ stores vulnerabilities in the indexer, not the manager.
				if indexerClient == nil {
					fmt.Println(color.YellowString("note:") + " vulnerability data is not available via the manager API (Wazuh 4.8+).")
					fmt.Println("Configure [indexer] in config.toml to query vulnerabilities from the indexer.")
					return
				}
				listVulnsFromIndexer(args[0], severity, limit)
				return
			}
			if output.Format == "json" {
				output.JSON(vulns)
				return
			}
			fmt.Printf("Showing %d of %d vulnerabilities\n\n", len(vulns), total)
			t := output.NewTable("CVE", "SEVERITY", "PACKAGE", "VERSION", "TITLE")
			for _, vv := range vulns {
				title := vv.Title
				if len(title) > 60 {
					title = title[:57] + "..."
				}
				t.Row(vv.CVE, output.SeverityBadge(vv.Severity), vv.Name, vv.Version, title)
			}
			t.Flush()
		},
	}
	listCmd.Flags().StringVar(&severity, "severity", "", "Filter by severity: critical, high, medium, low")
	listCmd.Flags().IntVar(&limit, "limit", 500, "Maximum number of results")
	cmd.AddCommand(listCmd)

	var sumLimit int
	summaryCmd := &cobra.Command{
		Use:   "summary <agent_id>",
		Short: "Show vulnerability counts grouped by severity",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// Always use indexer for summary on Wazuh 4.8+ since manager API is unreliable.
			if indexerClient != nil {
				summarizeVulnsFromIndexer(args[0], sumLimit)
				return
			}
			v := api.NewVulnAPI(managerClient)
			summary, err := v.Summary(args[0], "severity")
			if err != nil {
				if isVulnNotFound(err) {
					fmt.Println(color.YellowString("note:") + " configure [indexer] in config.toml to query vulnerabilities from the indexer (Wazuh 4.8+).")
					return
				}
				die(err)
			}
			if output.Format == "json" {
				output.JSON(summary)
				return
			}
			for k, val := range summary {
				fmt.Printf("%-12s %s\n", k+":", output.ColorSeverity(fmt.Sprintf("%v", val)))
			}
		},
	}
	summaryCmd.Flags().IntVar(&sumLimit, "limit", 5000, "Max vulnerabilities to aggregate")
	cmd.AddCommand(summaryCmd)

	return cmd
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
		die(err)
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
		t.Row(
			vv.Vuln.ID,
			output.SeverityBadge(vv.Vuln.Severity),
			fmt.Sprintf("%.1f", vv.Vuln.Score.Base),
			vv.Package.Name,
			vv.Package.Version,
		)
	}
	t.Flush()
}

func summarizeVulnsFromIndexer(agentID string, limit int) {
	vulns, total, err := indexerClient.Vulnerabilities(agentID, "", limit)
	if err != nil {
		die(err)
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
