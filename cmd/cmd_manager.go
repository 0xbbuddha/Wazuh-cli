package cmd

import (
	"flag"
	"fmt"
	"sort"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleManager(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"manager"})
		return
	}
	switch args[0] {
	case "info":
		managerInfo(args[1:])
	case "status":
		managerStatus(args[1:])
	case "logs":
		managerLogs(args[1:])
	default:
		printUnknownSub("manager", args[0])
	}
}

func managerInfo(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("manager info", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt

	m := api.NewManagerAPI(managerClient)
	info, err := m.Info()
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(info)
		return
	}
	output.Field("Version", info.Version)
	output.Field("Type", info.Type)
	output.Field("Path", info.Path)
	output.Field("Compiled", info.Compilation)
	output.Field("Max agents", info.MaxAgents)
	output.Field("OpenSSL", info.OpenSSL)
}

func managerStatus(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("manager status", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt

	m := api.NewManagerAPI(managerClient)
	status, err := m.Status()
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(status)
		return
	}
	daemons := make([]string, 0, len(status))
	for k := range status {
		daemons = append(daemons, k)
	}
	sort.Strings(daemons)
	t := output.NewTable("DAEMON", "STATUS")
	for _, d := range daemons {
		t.Row(d, output.ColorDaemon(status[d]))
	}
	t.Flush()
}

func managerLogs(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("manager logs", flag.ContinueOnError)
	lines := fs.Int("lines", 20, "Number of log entries to show")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt

	m := api.NewManagerAPI(managerClient)
	logs, err := m.Logs(*lines)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(logs)
		return
	}
	t := output.NewTable("TIMESTAMP", "LEVEL", "TAG", "DESCRIPTION")
	for _, l := range logs {
		t.Row(l.Timestamp, output.ColorDaemon(l.Level), l.Tag, l.Description)
	}
	t.Flush()
	fmt.Printf("\n%d log entries shown.\n", len(logs))
}
