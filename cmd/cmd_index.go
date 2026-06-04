package cmd

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

// safePatterns are index prefixes that can be deleted without losing security data.
// They are recreated automatically by Wazuh/OpenSearch.
var safePatterns = []string{
	"wazuh-monitoring-",
	"wazuh-statistics-",
	"wazuh-states-inventory-",
}

// protectedPatterns are never deleted - they contain alert and archive data.
var protectedPatterns = []string{
	"wazuh-alerts-",
	"wazuh-archives-",
}

func handleIndex(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"indices"})
		return
	}
	switch args[0] {
	case "list":
		indexList(args[1:])
	case "delete":
		indexDelete(args[1:])
	case "clean":
		indexClean(args[1:])
	default:
		printUnknownSub("indices", args[0])
	}
}

func indexList(args []string) {
	if !needsIndexer() {
		return
	}
	fs := flag.NewFlagSet("indices list", flag.ContinueOnError)
	filter := fs.String("filter", "", "Filter index names (substring)")
	health := fs.String("health", "", "Filter by health: red, yellow, green")
	if err := fs.Parse(args); err != nil {
		return
	}

	indices, err := indexerClient.Indices()
	if err != nil {
		printErr(err)
		return
	}

	t := output.NewTable("INDEX", "HEALTH", "STATUS", "DOCS", "SIZE")
	shown := 0
	for _, idx := range indices {
		if *filter != "" && !strings.Contains(idx.Index, *filter) {
			continue
		}
		if *health != "" && !strings.EqualFold(idx.Health, *health) {
			continue
		}
		t.Row(
			idx.Index,
			colorHealth(idx.Health),
			output.Dim(idx.Status),
			output.Dim(idx.DocsCount),
			idx.StoreSize,
		)
		shown++
	}
	t.Flush()

	if shown == 0 {
		printWarn("no indices found")
	} else {
		color.New(color.Faint).Printf("\n  %d indices\n\n", shown)
	}
}

func indexDelete(args []string) {
	if !needsIndexer() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: indices delete <index-name>"))
		return
	}
	name := args[0]

	printWarn(fmt.Sprintf("This will permanently delete index: %s", name))
	if !promptConfirm("Are you sure?") {
		fmt.Println("Aborted.")
		return
	}

	if err := indexerClient.DeleteIndex(name); err != nil {
		printErr(err)
		return
	}
	printOK(fmt.Sprintf("Index %q deleted.", name))
}

func indexClean(args []string) {
	if !needsIndexer() {
		return
	}
	fs := flag.NewFlagSet("indices clean", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "Show what would be deleted without deleting")
	if err := fs.Parse(args); err != nil {
		return
	}

	indices, err := indexerClient.Indices()
	if err != nil {
		printErr(err)
		return
	}

	var safe, protected, unknown []string
	for _, idx := range indices {
		if !strings.EqualFold(idx.Health, "red") {
			continue
		}
		cat := categorize(idx.Index)
		switch cat {
		case "safe":
			safe = append(safe, idx.Index)
		case "protected":
			protected = append(protected, idx.Index)
		default:
			unknown = append(unknown, idx.Index)
		}
	}

	total := len(safe) + len(protected) + len(unknown)
	if total == 0 {
		printOK("No red indices found - cluster looks healthy.")
		return
	}

	color.New(color.FgRed, color.Bold).Printf("\n  [!] %d red index/indices found\n\n", total)

	if len(safe) > 0 {
		color.New(color.FgYellow, color.Bold).Printf("  SAFE TO DELETE (%d):\n", len(safe))
		for _, idx := range safe {
			fmt.Printf("    %s  %s\n", color.RedString("x"), idx)
		}
		fmt.Println()
	}

	if len(protected) > 0 {
		color.New(color.FgGreen, color.Bold).Printf("  PROTECTED - will NOT be touched (%d):\n", len(protected))
		for _, idx := range protected {
			fmt.Printf("    %s  %s\n", color.GreenString("*"), idx)
		}
		fmt.Println()
	}

	if len(unknown) > 0 {
		color.New(color.FgYellow, color.Bold).Printf("  UNKNOWN - manual review needed (%d):\n", len(unknown))
		for _, idx := range unknown {
			fmt.Printf("    %s  %s\n", color.YellowString("?"), idx)
		}
		fmt.Println()
	}

	if len(safe) == 0 {
		printWarn("No safe indices to delete automatically. Review the lists above.")
		return
	}

	if *dryRun {
		printInfo(fmt.Sprintf("Dry run: would delete %d indices.", len(safe)))
		return
	}

	if !promptConfirm(fmt.Sprintf("Delete %d safe indices?", len(safe))) {
		fmt.Println("Aborted.")
		return
	}

	deleted := 0
	for _, idx := range safe {
		if err := indexerClient.DeleteIndex(idx); err != nil {
			printErr(fmt.Errorf("%s: %w", idx, err))
		} else {
			deleted++
		}
	}
	printOK(fmt.Sprintf("%d indices deleted.", deleted))

	fmt.Println()
	printInfo("Waiting 30s for cluster to rebalance...")
	time.Sleep(30 * time.Second)

	h, err := indexerClient.ClusterHealth()
	if err != nil {
		printErr(fmt.Errorf("could not fetch cluster health: %w", err))
		return
	}
	fmt.Println()
	printSection("Cluster health after cleanup")
	output.Field("Status", colorHealth(h.Status))
	output.Field("Nodes", fmt.Sprintf("%d total, %d data", h.NumberOfNodes, h.NumberOfDataNodes))
	output.Field("Shards", fmt.Sprintf("%d active, %d relocating, %d unassigned",
		h.ActiveShards, h.RelocatingShards, h.UnassignedShards))
	if h.UnassignedShards > 0 {
		printWarn("Some shards still unassigned - wait a few more minutes and run again.")
	}
	fmt.Println()
}

func categorize(name string) string {
	for _, p := range protectedPatterns {
		if strings.HasPrefix(name, p) {
			return "protected"
		}
	}
	for _, p := range safePatterns {
		if strings.HasPrefix(name, p) {
			return "safe"
		}
	}
	return "unknown"
}

func colorHealth(s string) string {
	switch strings.ToLower(s) {
	case "green":
		return color.GreenString(s)
	case "yellow":
		return color.YellowString(s)
	case "red":
		return color.New(color.FgRed, color.Bold).Sprint(s)
	default:
		return s
	}
}
