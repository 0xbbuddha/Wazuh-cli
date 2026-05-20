package cmd

import (
	"fmt"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleStatus(_ []string) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	fmt.Println()

	// Manager
	bold.Printf("  Manager\n")
	if managerClient == nil {
		output.Field("    Status", color.New(color.FgRed, color.Bold).Sprint("not connected"))
		output.Field("    Run", "'config init' to configure")
		fmt.Println()
	} else {
		output.Field("    URL", cfg.APIURL)
		m := api.NewManagerAPI(managerClient)
		info, err := m.Info()
		if err != nil {
			output.Field("    Status", color.New(color.FgRed, color.Bold).Sprint("unreachable"))
			output.Field("    Error", err.Error())
		} else {
			output.Field("    Status", color.New(color.FgGreen, color.Bold).Sprint("connected"))
			output.Field("    Version", info.Version)
			output.Field("    Type", info.Type)
		}
		fmt.Println()

		// Agents
		bold.Printf("  Agents\n")
		a := api.NewAgentsAPI(managerClient)
		summary, err := a.Summary()
		if err != nil {
			output.Field("    Status", color.New(color.FgRed).Sprint("unavailable"))
		} else {
			output.Field("    Active", color.New(color.FgGreen, color.Bold).Sprintf("%d", summary.Connection.Active))
			output.Field("    Disconnected", colorCountIf(summary.Connection.Disconnected > 0, summary.Connection.Disconnected))
			output.Field("    Pending", colorCountIf(summary.Connection.Pending > 0, summary.Connection.Pending))
			output.Field("    Total", color.New(color.Bold).Sprintf("%d", summary.Connection.Total))
		}
		fmt.Println()

		// Daemon highlights
		bold.Printf("  Daemons\n")
		status, err := m.Status()
		if err != nil {
			output.Field("    Status", color.New(color.FgRed).Sprint("unavailable"))
		} else {
			key := []string{"wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-apid"}
			for _, d := range key {
				if s, ok := status[d]; ok {
					output.Field("    "+d, output.ColorDaemon(s))
				}
			}
			stopped := 0
			for _, s := range status {
				if s == "stopped" {
					stopped++
				}
			}
			if stopped > 0 {
				output.Field("    Note", color.YellowString("%d daemon(s) stopped - run 'manager status' for details", stopped))
			}
		}
		fmt.Println()
	}

	// Indexer
	bold.Printf("  Indexer\n")
	if indexerClient == nil {
		output.Field("    Status", dim.Sprint("not configured"))
		output.Field("    Tip", "add [indexer] section to config.toml")
	} else {
		h, err := indexerClient.ClusterHealth()
		if err != nil {
			output.Field("    Status", color.New(color.FgRed, color.Bold).Sprint("unreachable"))
			output.Field("    Error", err.Error())
		} else {
			output.Field("    Status", colorIndexerStatus(h.Status))
			output.Field("    Cluster", h.ClusterName)
			output.Field("    Nodes", fmt.Sprintf("%d total, %d data", h.NumberOfNodes, h.NumberOfDataNodes))
			output.Field("    Shards", fmt.Sprintf("%d active, %d unassigned", h.ActiveShards, h.UnassignedShards))
		}
	}
	fmt.Println()
}

func colorCountIf(warn bool, n int) string {
	if warn {
		return color.New(color.FgYellow, color.Bold).Sprintf("%d", n)
	}
	return color.New(color.Faint).Sprintf("%d", n)
}
