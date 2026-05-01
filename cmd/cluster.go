package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Cluster status and nodes",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show whether Wazuh manager clustering is enabled and running",
		Run: func(cmd *cobra.Command, args []string) {
			cl := api.NewClusterAPI(managerClient)
			s, err := cl.Status()
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(s)
				return
			}
			output.Field("Enabled", s.Enabled)
			output.Field("Running", s.Running)
			if s.Enabled == "no" {
				fmt.Println()
				color.New(color.Faint).Println("Wazuh manager cluster is disabled (single-node setup).")
				fmt.Println("Use 'cluster indexer' to check the OpenSearch/Indexer cluster.")
			}
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "nodes",
		Short: "List Wazuh manager cluster nodes",
		Run: func(cmd *cobra.Command, args []string) {
			cl := api.NewClusterAPI(managerClient)
			nodes, err := cl.Nodes()
			if err != nil {
				if isClusterDisabled(err) {
					color.New(color.Faint).Println("Wazuh manager cluster is disabled.")
					fmt.Println("Use 'cluster indexer' to check the OpenSearch/Indexer cluster.")
					return
				}
				die(err)
			}
			if output.Format == "json" {
				output.JSON(nodes)
				return
			}
			t := output.NewTable("NAME", "TYPE", "IP", "VERSION", "STATUS")
			for _, n := range nodes {
				t.Row(n.Name, n.Type, n.IP, n.Version, output.ColorStatus(n.Status))
			}
			t.Flush()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "health",
		Short: "Show Wazuh manager cluster health",
		Run: func(cmd *cobra.Command, args []string) {
			cl := api.NewClusterAPI(managerClient)
			h, err := cl.Health()
			if err != nil {
				if isClusterDisabled(err) {
					color.New(color.Faint).Println("Wazuh manager cluster is disabled.")
					fmt.Println("Use 'cluster indexer' to check the OpenSearch/Indexer cluster.")
					return
				}
				die(err)
			}
			if output.Format == "json" {
				output.JSON(h)
				return
			}

			fmt.Printf("%d nodes in cluster\n\n", len(h))
			t := output.NewTable("NODE", "TYPE", "IP", "VERSION")
			for _, n := range h {
				t.Row(n.Info.Name, n.Info.Type, n.Info.IP, n.Info.Version)
			}
			t.Flush()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "indexer",
		Short: "Show OpenSearch/Indexer cluster health (port 9200)",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if indexerClient == nil {
				fmt.Fprintln(os.Stderr, color.RedString("Error:")+" indexer.url is not configured in config.toml")
				os.Exit(1)
			}
			output.Format = outputFormat
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			h, err := indexerClient.ClusterHealth()
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(h)
				return
			}
			output.Field("Cluster name", h.ClusterName)
			output.Field("Status", colorIndexerStatus(h.Status))
			output.Field("Nodes", fmt.Sprintf("%d total, %d data", h.NumberOfNodes, h.NumberOfDataNodes))
			output.Field("Shards", fmt.Sprintf("%d active (%d primary), %d relocating, %d unassigned",
				h.ActiveShards, h.ActivePrimaryShards, h.RelocatingShards, h.UnassignedShards))
			output.Field("Active shards", fmt.Sprintf("%.1f%%", h.ActiveShardsPercent))
			if h.TimedOut {
				fmt.Println(color.YellowString("warning: cluster health check timed out"))
			}
		},
	})

	return cmd
}

func isClusterDisabled(err error) bool {
	return strings.Contains(err.Error(), "3013") || strings.Contains(err.Error(), "Cluster is not running")
}

func colorIndexerStatus(s string) string {
	switch strings.ToLower(s) {
	case "green":
		return color.New(color.FgGreen, color.Bold).Sprint(s)
	case "yellow":
		return color.New(color.FgYellow, color.Bold).Sprint(s)
	case "red":
		return color.New(color.FgRed, color.Bold).Sprint(s)
	default:
		return s
	}
}
