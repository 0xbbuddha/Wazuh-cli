package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleCluster(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"cluster"})
		return
	}
	switch args[0] {
	case "status":
		clusterStatus(args[1:])
	case "nodes":
		clusterNodes(args[1:])
	case "health":
		clusterHealth(args[1:])
	case "indexer":
		clusterIndexer(args[1:])
	default:
		printUnknownSub("cluster", args[0])
	}
}

func clusterStatus(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("cluster status", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt

	cl := api.NewClusterAPI(managerClient)
	s, err := cl.Status()
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(s)
		return
	}
	output.Field("Enabled", s.Enabled)
	output.Field("Running", s.Running)
	if s.Enabled == "no" {
		fmt.Println()
		brandDim.Println("Wazuh manager cluster is disabled (single-node setup).")
		fmt.Println("Use 'cluster indexer' to check the OpenSearch/Indexer cluster.")
	}
}

func clusterNodes(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("cluster nodes", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt

	cl := api.NewClusterAPI(managerClient)
	nodes, err := cl.Nodes()
	if err != nil {
		if isClusterDisabled(err) {
			brandDim.Println("Wazuh manager cluster is disabled.")
			fmt.Println("Use 'cluster indexer' to check the OpenSearch/Indexer cluster.")
			return
		}
		printErr(err)
		return
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
}

func clusterHealth(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("cluster health", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt

	cl := api.NewClusterAPI(managerClient)
	h, err := cl.Health()
	if err != nil {
		if isClusterDisabled(err) {
			brandDim.Println("Wazuh manager cluster is disabled.")
			fmt.Println("Use 'cluster indexer' to check the OpenSearch/Indexer cluster.")
			return
		}
		printErr(err)
		return
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
}

func clusterIndexer(args []string) {
	if !needsIndexer() {
		return
	}
	fs := flag.NewFlagSet("cluster indexer", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt

	h, err := indexerClient.ClusterHealth()
	if err != nil {
		printErr(err)
		return
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
		printWarn("cluster health check timed out")
	}
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
