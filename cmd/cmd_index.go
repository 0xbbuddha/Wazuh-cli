package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

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
	default:
		printUnknownSub("indices", args[0])
	}
}

func indexList(args []string) {
	if !needsIndexer() {
		return
	}
	fs := flag.NewFlagSet("index list", flag.ContinueOnError)
	filter := fs.String("filter", "", "Filter index names (substring)")
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
		health := idx.Health
		switch health {
		case "green":
			health = color.GreenString(health)
		case "yellow":
			health = color.YellowString(health)
		case "red":
			health = color.RedString(health)
		}
		t.Row(
			idx.Index,
			health,
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
		printErr(fmt.Errorf("usage: index delete <index-name>"))
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
