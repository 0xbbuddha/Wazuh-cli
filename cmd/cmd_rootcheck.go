package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleRootcheck(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"rootcheck"})
		return
	}
	switch args[0] {
	case "results":
		rootcheckResults(args[1:])
	case "last":
		rootcheckLast(args[1:])
	case "scan":
		rootcheckScan(args[1:])
	case "clear":
		rootcheckClear(args[1:])
	default:
		printUnknownSub("rootcheck", args[0])
	}
}

func rootcheckResults(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: rootcheck results <agent_id> [--status passed|failed] [--search TEXT] [--limit N] [--page N]"))
		return
	}
	agentID := args[0]

	fs := flag.NewFlagSet("rootcheck results", flag.ContinueOnError)
	status := fs.String("status", "", "Filter by status: passed or failed")
	search := fs.String("search", "", "Filter by event text (substring)")
	limit := fs.Int("limit", 30, "Results per page")
	page := fs.Int("page", 1, "Page number")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt
	offset := (*page - 1) * *limit

	rc := api.NewRootcheckAPI(managerClient)
	results, total, err := rc.Results(agentID, *status, *search, *limit, offset)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(results)
		return
	}

	totalPages := (total + *limit - 1) / *limit
	if totalPages == 0 {
		totalPages = 1
	}
	output.ShowCount(len(results), total, fmt.Sprintf("rootcheck results - page %d/%d", *page, totalPages))

	t := output.NewTable("STATUS", "EVENT", "CIS", "DATE")
	for _, r := range results {
		t.Row(
			colorRootcheckStatus(r.Status),
			output.Truncate(strings.TrimPrefix(r.Event, "System Audit: "), 60),
			output.Dim(output.Truncate(r.CIS, 20)),
			output.Dim(output.Truncate(r.DateLast, 19)),
		)
	}
	t.Flush()

	if *page < totalPages {
		color.New(color.Faint).Printf("\n  --page %d/%d  (--limit %d to change page size)\n\n", *page, totalPages, *limit)
	}
}

func rootcheckLast(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: rootcheck last <agent_id>"))
		return
	}

	rc := api.NewRootcheckAPI(managerClient)
	scan, err := rc.LastScan(args[0])
	if err != nil {
		printErr(err)
		return
	}

	printSection("Last Rootcheck Scan - Agent " + args[0])
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

func rootcheckScan(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: rootcheck scan <agent_id>"))
		return
	}
	agentID := args[0]

	if !promptConfirm(fmt.Sprintf("Trigger rootcheck scan on agent %s?", agentID)) {
		return
	}

	rc := api.NewRootcheckAPI(managerClient)
	if err := rc.Scan(agentID); err != nil {
		printErr(err)
		return
	}
	printOK(fmt.Sprintf("Rootcheck scan triggered on agent %s", agentID))
}

func rootcheckClear(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: rootcheck clear <agent_id>"))
		return
	}
	agentID := args[0]

	if !promptConfirm(fmt.Sprintf("Clear rootcheck database for agent %s? This cannot be undone.", agentID)) {
		return
	}

	rc := api.NewRootcheckAPI(managerClient)
	if err := rc.Clear(agentID); err != nil {
		printErr(err)
		return
	}
	printOK(fmt.Sprintf("Rootcheck database cleared for agent %s", agentID))
}

func colorRootcheckStatus(s string) string {
	switch strings.ToLower(s) {
	case "passed":
		return color.GreenString(s)
	case "failed":
		return color.RedString(s)
	default:
		return s
	}
}
