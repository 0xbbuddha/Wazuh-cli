package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fatih/color"
)

type cmdEntry struct {
	short   string
	handler func(args []string)
}

var registry map[string]cmdEntry

func init() {
	registry = map[string]cmdEntry{
		"agent":        {"Manage Wazuh agents", handleAgent},
		"alerts":       {"Query alerts from the Wazuh Indexer", handleAlerts},
		"ar":           {"Active response - trigger actions on agents", handleAR},
		"cluster":      {"Cluster status and nodes", handleCluster},
		"config":       {"Show or initialize configuration", handleConfig},
		"dashboard":    {"Interactive TUI dashboard", handleDashboard},
		"groups":       {"Manage agent groups", handleGroups},
		"logtest":      {"Test a log against Wazuh rules", handleLogtest},
		"manager":      {"Manager information and status", handleManager},
		"status":       {"Quick overview: manager, agents, indexer", handleStatus},
		"rules":        {"Browse detection rules", handleRules},
		"sca":          {"Security Configuration Assessment results", handleSCA},
		"syscollector": {"System inventory for an agent", handleSyscollector},
		"syscheck":     {"File Integrity Monitoring (FIM) results", handleSyscheck},
		"vuln":         {"Vulnerability detection results", handleVuln},
		"help":         {"Show available commands", handleHelp},
		"version":      {"Print version", func(_ []string) { fmt.Printf("wazuh-cli %s\n", cliVersion) }},
		"clear":        {"Clear the terminal screen", func(_ []string) { fmt.Print("\033[2J\033[3J\033[H") }},
	}
}

func dispatch(line string) {
	if strings.HasPrefix(line, "!") {
		runShell(strings.TrimSpace(line[1:]))
		return
	}
	parts := splitArgs(line)
	if len(parts) == 0 {
		return
	}
	entry, ok := registry[parts[0]]
	if !ok {
		fmt.Printf("%s Unknown command %q - type 'help' for available commands\n",
			color.New(color.FgYellow, color.Bold).Sprint("[?]"), parts[0])
		return
	}
	entry.handler(parts[1:])
}

func runShell(command string) {
	if command == "" {
		printErr(fmt.Errorf("usage: !<command>  e.g. !ping 1.2.3.4"))
		return
	}
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			brandDim.Printf("[!] exited with code %d\n", exit.ExitCode())
		} else {
			printErr(err)
		}
	}
}

// splitArgs splits a line into tokens, respecting single- and double-quoted strings.
func splitArgs(line string) []string {
	var args []string
	var cur strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, r := range line {
		switch {
		case inQuote:
			if r == quoteChar {
				inQuote = false
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			inQuote = true
			quoteChar = r
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}
