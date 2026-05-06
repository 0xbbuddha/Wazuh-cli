package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

type arAction struct {
	command     string
	needsIP     bool
	description string
}

var arActions = map[string]arAction{
	"restart":    {"restart-wazuh0", false, "Restart the Wazuh agent service"},
	"block-ip":   {"firewall-drop0", true, "Block an IP address via iptables/firewall"},
	"unblock-ip": {"firewall-drop1", true, "Remove an IP block"},
	"host-deny":  {"host-deny0", true, "Add IP to /etc/hosts.deny"},
	"host-allow": {"host-deny1", true, "Remove IP from /etc/hosts.deny"},
	"route-null": {"route-null0", true, "Add a null route for an IP (traffic black-hole)"},
}

var arActionOrder = []string{"restart", "block-ip", "unblock-ip", "host-deny", "host-allow", "route-null"}

func handleAR(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"ar"})
		return
	}
	switch args[0] {
	case "list":
		arList()
	case "run":
		arRun(args[1:])
	default:
		printUnknownSub("ar", args[0])
	}
}

func arList() {
	t := output.NewTable("ACTION", "WAZUH COMMAND", "ARGS", "DESCRIPTION")
	for _, name := range arActionOrder {
		a := arActions[name]
		argsCol := "none"
		if a.needsIP {
			argsCol = "<ip>"
		}
		t.Row(name, a.command, argsCol, a.description)
	}
	t.Flush()
}

func arRun(args []string) {
	if !needsManager() {
		return
	}
	if len(args) < 2 {
		printErr(fmt.Errorf("usage: ar run <agent_id|all> <action> [<ip>] [-f]"))
		return
	}

	fs := flag.NewFlagSet("ar run", flag.ContinueOnError)
	force := fs.Bool("f", false, "Skip confirmation for mass operations")
	// positional args are before flags — parse them manually
	agentID := args[0]
	actionName := args[1]
	remaining := args[2:]
	if err := fs.Parse(remaining); err != nil {
		return
	}

	action, ok := arActions[actionName]
	if !ok {
		printErr(fmt.Errorf("unknown action %q — run 'ar list' to see available actions", actionName))
		return
	}

	var ip string
	positional := fs.Args()
	if action.needsIP {
		if len(positional) == 0 {
			printErr(fmt.Errorf("action %q requires an IP address: ar run %s %s <ip>",
				actionName, agentID, actionName))
			return
		}
		ip = positional[0]
	}

	if agentID == "all" && !*force {
		fmt.Printf("%s This will run %q on ALL agents.\n", color.YellowString("[!]"), actionName)
		fmt.Print("Continue? [y/N] ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("Aborted.")
			return
		}
	}

	req := api.ARRequest{
		Command: action.command,
		Alert:   &api.ARAlert{},
	}
	if ip != "" {
		req.Alert = &api.ARAlert{
			Data: map[string]string{"srcip": ip},
		}
	}

	ar := api.NewActiveResponseAPI(managerClient)
	result, err := ar.Run(agentID, req)
	if err != nil {
		printErr(err)
		return
	}

	if result.TotalFailed > 0 {
		color.New(color.FgRed, color.Bold).Printf("[!] Failed ")
		fmt.Printf("(%d affected, %d failed)\n", result.TotalAffected, result.TotalFailed)
		for _, f := range result.FailedItems {
			fmt.Printf("  agents %v — [%d] %s\n", f.IDs, f.Error.Code, f.Error.Message)
		}
		return
	}

	target := "agent " + agentID
	if agentID == "all" {
		target = fmt.Sprintf("%d agent(s)", result.TotalAffected)
	}
	printOK(fmt.Sprintf("%s executed on %s", actionName, target))
}
