package cmd

import (
	"fmt"
	"sort"

	"github.com/fatih/color"
)

var generalCmds = map[string]struct{}{
	"help":    {},
	"clear":   {},
	"version": {},
}

func handleHelp(args []string) {
	if len(args) > 0 {
		showCommandHelp(args[0])
		return
	}

	// Wazuh commands
	var wazuh []string
	for name := range registry {
		if _, isGeneral := generalCmds[name]; !isGeneral {
			wazuh = append(wazuh, name)
		}
	}
	sort.Strings(wazuh)

	fmt.Println()
	fmt.Printf("  %s\n\n", wazuhBlue("COMMANDS"))
	for _, name := range wazuh {
		fmt.Printf("    \033[38;5;33m%-16s\033[0m  %s\n", name, registry[name].short)
	}

	// General commands
	fmt.Println()
	fmt.Printf("  %s\n\n", wazuhBlue("GENERAL"))
	fmt.Printf("    \033[38;5;33m%-16s\033[0m  %s\n", "!<cmd>", "Run a shell command  (!ping 1.2.3.4, !cat /etc/hosts)")
	fmt.Printf("    \033[38;5;33m%-16s\033[0m  %s\n", "help [command]", "Show this help or subcommands for a command")
	fmt.Printf("    \033[38;5;33m%-16s\033[0m  %s\n", "version", "Print current version")
	fmt.Printf("    \033[38;5;33m%-16s\033[0m  %s\n", "clear", "Clear the terminal screen")
	fmt.Printf("    \033[38;5;33m%-16s\033[0m  %s\n", "exit / quit", "Leave the REPL")

	fmt.Println()
	fmt.Printf("  %s\n\n", wazuhBlue("TIPS"))
	fmt.Printf("    %-16s  %s\n", "-o json", "Append to any command for JSON output")
	fmt.Printf("    %-16s  %s\n", "Tab", "Autocomplete commands and subcommands")
	fmt.Println()
}

var subHelp = map[string][]struct{ sub, desc string }{
	"agent": {
		{"list", "List all agents [--status STATUS] [--group GROUP] [--limit N]"},
		{"get <id>", "Get detailed info for an agent"},
		{"restart <id>", "Restart an agent"},
		{"summary", "Show agent connection and config-sync summary"},
		{"enroll", "Register agent and show full install command [--name NAME] [--os OS]"},
		{"remove <id>", "Remove an agent [-f to skip confirmation]"},
		{"upgrade <id>", "Upgrade agent [--version V] [--no-watch]"},
		{"groups", "List agent groups"},
	},
	"alerts": {
		{"list", "List recent alerts [--limit N] [--level N] [--agent ID] [--watch] [--interval N]"},
		{"heatmap", "7-day × 24-hour alert volume heatmap [--agent ID]"},
		{"search <query>", "Full-text search across alert logs [--limit N]"},
	},
	"ar": {
		{"list", "List available active response actions"},
		{"run <agent|all> <action> [<ip>]", "Execute an active response action [-f to skip confirmation]"},
	},
	"cluster": {
		{"status", "Show whether clustering is enabled"},
		{"nodes", "List cluster nodes"},
		{"health", "Show cluster health"},
		{"indexer", "Show OpenSearch/Indexer cluster health"},
	},
	"config": {
		{"show", "Display current configuration"},
		{"init", "Interactive wizard to create config.toml"},
	},
	"dashboard": {
		{"(no subcommand)", "Launch the interactive TUI [--refresh N]"},
	},
	"decoder": {
		{"list", "List enabled decoders [--search NAME] [--limit N] [--page N]"},
		{"show <name>", "Show full details for a decoder (parent, regex, order, prematch)"},
	},
	"indices": {
		{"list", "List all wazuh-* indices [--filter NAME]"},
		{"delete <name>", "Delete an index (irreversible, requires confirmation)"},
	},
	"groups": {
		{"list", "List all groups"},
		{"agents <group>", "List agents in a group"},
		{"create <name>", "Create a new group"},
		{"delete <name>", "Delete a group [-f to skip confirmation]"},
		{"assign <agent_id> <group>", "Assign agent to group"},
		{"unassign <agent_id> <group>", "Remove agent from group"},
		{"config <name>", "Show agent.conf for a group"},
		{"config-edit <name>", "Edit agent.conf in $EDITOR and upload on save"},
	},
	"logtest": {
		{"[log event]", "Test a single log line"},
		{"-f <file>", "Test all lines in a file"},
		{"(no args)", "Interactive REPL or stdin pipe"},
	},
	"manager": {
		{"info", "Show manager version and build info"},
		{"status", "Show status of all Wazuh daemons"},
		{"logs", "Show recent manager logs [--lines N]"},
	},
	"mitre": {
		{"techniques", "List ATT&CK techniques [--search NAME] [--tactic TACTIC] [--limit N] [--page N]"},
		{"tactics", "List all ATT&CK tactics [--search NAME]"},
		{"groups", "List threat actor groups [--search NAME] [--limit N] [--page N]"},
		{"software", "List malware and tools [--search NAME] [--limit N] [--page N]"},
		{"show <id>", "Show full detail for a technique (T1059, T1059.001, ...)"},
	},
	"rules": {
		{"list", "List rules [--level N] [--group G] [--limit N]"},
		{"get <id>", "Get details for a specific rule"},
		{"groups", "List all rule groups"},
	},
	"sca": {
		{"list <agent_id>", "List SCA policies and scores for an agent"},
		{"checks <agent_id> <policy_id>", "Show detailed check results for a policy"},
	},
	"syscheck": {
		{"files <agent_id>", "List FIM events [--event added|modified|deleted] [--search PATH] [--limit N] [--page N]"},
		{"last <agent_id>", "Show date of last FIM scan"},
		{"scan <agent_id>", "Trigger a FIM scan on an agent"},
		{"clear <agent_id>", "Wipe the FIM database for an agent (irreversible)"},
	},
	"syscollector": {
		{"hardware <agent_id>", "CPU and RAM information"},
		{"os <agent_id>", "OS information"},
		{"packages <agent_id>", "Installed packages [--search S] [--limit N]"},
		{"ports <agent_id>", "Open / listening ports [--limit N]"},
		{"processes <agent_id>", "Running processes [--limit N]"},
		{"netaddr <agent_id>", "Network addresses"},
	},
	"vuln": {
		{"list <agent_id>", "List detected vulnerabilities [--severity S] [--limit N]"},
		{"summary <agent_id>", "Vulnerability counts by severity [--limit N]"},
	},
}

func showCommandHelp(name string) {
	entry, ok := registry[name]
	if !ok {
		fmt.Printf("%s Unknown command %q\n", color.New(color.FgYellow, color.Bold).Sprint("[?]"), name)
		return
	}
	fmt.Println()
	fmt.Printf("  %s - %s\n", wazuhBlue(name), entry.short)
	subs, ok := subHelp[name]
	if !ok || len(subs) == 0 {
		fmt.Println()
		return
	}
	fmt.Println()
	maxW := 0
	for _, s := range subs {
		if len(s.sub) > maxW {
			maxW = len(s.sub)
		}
	}
	format := fmt.Sprintf("    \033[38;5;33m%%-%ds\033[0m  %%s\n", maxW)
	for _, s := range subs {
		fmt.Printf(format, s.sub, s.desc)
	}
	fmt.Println()
	fmt.Printf("  Append \033[38;5;33m-o json\033[0m to most commands for JSON output.\n\n")
}
