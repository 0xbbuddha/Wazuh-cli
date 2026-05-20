package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleSyscheck(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"syscheck"})
		return
	}
	switch args[0] {
	case "files":
		syscheckFiles(args[1:])
	case "last":
		syscheckLast(args[1:])
	case "scan":
		syscheckScan(args[1:])
	default:
		printUnknownSub("syscheck", args[0])
	}
}

func colorEvent(e string) string {
	switch strings.ToLower(e) {
	case "added":
		return color.New(color.FgGreen, color.Bold).Sprint(e)
	case "modified":
		return color.New(color.FgYellow, color.Bold).Sprint(e)
	case "deleted":
		return color.New(color.FgRed, color.Bold).Sprint(e)
	default:
		return e
	}
}

func syscheckFiles(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: syscheck files <agent_id> [--event added|modified|deleted] [--search <path>] [--limit N] [--page N] [-o json]"))
		return
	}
	agentID := args[0]

	fs := flag.NewFlagSet("syscheck files", flag.ContinueOnError)
	event := fs.String("event", "", "Filter by event: added, modified, deleted")
	search := fs.String("search", "", "Filter by file path (substring)")
	limit := fs.Int("limit", 50, "Results per page")
	page := fs.Int("page", 1, "Page number")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt
	offset := (*page - 1) * *limit

	sc := api.NewSyscheckAPI(managerClient)
	files, total, err := sc.Files(agentID, *event, *search, *limit, offset)
	if err != nil {
		printErr(err)
		return
	}

	if output.Format == "json" {
		output.JSON(files)
		return
	}

	totalPages := (total + *limit - 1) / *limit
	if totalPages == 0 {
		totalPages = 1
	}
	output.ShowCount(len(files), total, fmt.Sprintf("FIM events (page %d/%d)", *page, totalPages))

	t := output.NewTable("EVENT", "TYPE", "FILE", "SIZE", "MTIME")
	for _, f := range files {
		size := ""
		if f.Size > 0 {
			size = fmt.Sprintf("%d", f.Size)
		}
		mtime := output.Truncate(f.Mtime, 19)
		if mtime == "" {
			mtime = output.Truncate(f.Date, 19)
		}
		t.Row(
			colorEvent(f.Event),
			output.Dim(f.Type),
			output.Truncate(f.File, 60),
			output.Dim(size),
			output.Dim(mtime),
		)
	}
	t.Flush()

	if *page < totalPages {
		fmt.Printf("\n%s use --page %d for next page\n",
			color.New(color.Faint).Sprint("tip:"), *page+1)
	}
}

func syscheckLast(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: syscheck last <agent_id>"))
		return
	}
	agentID := args[0]

	sc := api.NewSyscheckAPI(managerClient)
	scan, err := sc.LastScan(agentID)
	if err != nil {
		printErr(err)
		return
	}

	printSection("Last FIM Scan - Agent " + agentID)
	if scan == nil || (scan.Start == "" && scan.End == "") {
		printWarn("No scan recorded for this agent")
		return
	}
	output.Field("Start", scan.Start)
	output.Field("End", scan.End)
	if scan.Start != "" && scan.End != "" {
		printOK("Scan completed")
	} else if scan.Start != "" {
		printWarn("Scan in progress or incomplete")
	}
}

func syscheckScan(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: syscheck scan <agent_id>"))
		return
	}
	agentID := args[0]

	if !promptConfirm(fmt.Sprintf("Trigger FIM scan on agent %s?", agentID)) {
		return
	}

	sc := api.NewSyscheckAPI(managerClient)
	if err := sc.Scan(agentID); err != nil {
		printErr(err)
		return
	}
	printOK(fmt.Sprintf("FIM scan triggered on agent %s", agentID))
}
