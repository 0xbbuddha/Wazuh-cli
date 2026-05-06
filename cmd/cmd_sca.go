package cmd

import (
	"flag"
	"fmt"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleSCA(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"sca"})
		return
	}
	switch args[0] {
	case "list":
		scaList(args[1:])
	case "checks":
		scaChecks(args[1:])
	default:
		printUnknownSub("sca", args[0])
	}
}

func scaList(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: sca list <agent_id>"))
		return
	}
	fs := flag.NewFlagSet("sca list", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	s := api.NewSCAAPI(managerClient)
	policies, err := s.List(agentID)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(policies)
		return
	}
	t := output.NewTable("POLICY", "NAME", "PASS", "FAIL", "INVALID", "SCORE", "LAST SCAN")
	for _, p := range policies {
		t.Row(p.PolicyID, output.Truncate(p.Name, 40),
			fmt.Sprintf("%d", p.PassCount),
			fmt.Sprintf("%d", p.FailCount),
			fmt.Sprintf("%d", p.InvalidCount),
			output.ProgressBar(p.Score),
			p.EndScan)
	}
	t.Flush()
}

func scaChecks(args []string) {
	if !needsManager() {
		return
	}
	if len(args) < 2 {
		printErr(fmt.Errorf("usage: sca checks <agent_id> <policy_id>"))
		return
	}
	fs := flag.NewFlagSet("sca checks", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	policyID := args[1]
	if err := fs.Parse(args[2:]); err != nil {
		return
	}
	output.Format = *outFmt

	s := api.NewSCAAPI(managerClient)
	checks, total, err := s.Checks(agentID, policyID)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(checks)
		return
	}
	output.ShowCount(len(checks), total, "checks")
	t := output.NewTable("ID", "RESULT", "TITLE")
	for _, ch := range checks {
		t.Row(fmt.Sprintf("%d", ch.ID), output.ColorResult(ch.Result), output.Truncate(ch.Title, 60))
	}
	t.Flush()
}
