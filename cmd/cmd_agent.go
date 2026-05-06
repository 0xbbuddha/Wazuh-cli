package cmd

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleAgent(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"agent"})
		return
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list":
		agentList(rest)
	case "get":
		agentGet(rest)
	case "restart":
		agentRestart(rest)
	case "summary":
		agentSummary(rest)
	case "add":
		agentAdd(rest)
	case "remove":
		agentRemove(rest)
	case "upgrade":
		agentUpgrade(rest)
	case "groups":
		agentGroups(rest)
	default:
		printUnknownSub("agent", sub)
	}
}

func agentList(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("agent list", flag.ContinueOnError)
	status := fs.String("status", "", "Filter by status: active, disconnected, never_connected, pending")
	group := fs.String("group", "", "Filter by group name")
	limit := fs.Int("limit", 500, "Maximum number of results")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt

	a := api.NewAgentsAPI(managerClient)
	agents, total, err := a.List(*status, *group, *limit)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(agents)
		return
	}
	output.ShowCount(len(agents), total, "agents")
	t := output.NewTable("ID", "NAME", "STATUS", "IP", "OS", "VERSION", "GROUP")
	for _, ag := range agents {
		t.Row(output.Dim(ag.ID), output.Cyan(ag.Name), output.ColorStatus(ag.Status),
			output.Dim(ag.IP),
			output.Dim(strings.TrimSpace(ag.Os.Name+" "+ag.Os.Version)),
			output.Dim(ag.Version), strings.Join(ag.Group, ","))
	}
	t.Flush()
}

func agentGet(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: agent get <agent_id> [-o json]"))
		return
	}
	fs := flag.NewFlagSet("agent get", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	agentID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	a := api.NewAgentsAPI(managerClient)
	ag, err := a.Get(agentID)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(ag)
		return
	}
	output.Field("ID", ag.ID)
	output.Field("Name", ag.Name)
	output.Field("Status", output.ColorStatus(ag.Status))
	output.Field("IP", ag.IP)
	output.Field("Manager", ag.Manager)
	output.Field("Node", ag.NodeName)
	output.Field("OS", ag.Os.Name+" "+ag.Os.Version+" ("+ag.Os.Arch+")")
	output.Field("Platform", ag.Os.Platform)
	output.Field("Version", ag.Version)
	output.Field("Groups", strings.Join(ag.Group, ", "))
	output.Field("Date added", ag.DateAdd)
	output.Field("Last keepalive", ag.LastKeepAlive)
}

func agentRestart(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: agent restart <agent_id>"))
		return
	}
	a := api.NewAgentsAPI(managerClient)
	if err := a.Restart(args[0]); err != nil {
		printErr(err)
		return
	}
	printOK(fmt.Sprintf("Agent %s restart requested", color.GreenString(args[0])))
}

func agentSummary(_ []string) {
	if !needsManager() {
		return
	}
	a := api.NewAgentsAPI(managerClient)
	s, err := a.Summary()
	if err != nil {
		printErr(err)
		return
	}
	printSection("Connection status")
	output.Field("  Active", color.GreenString("%d", s.Connection.Active))
	output.Field("  Disconnected", color.RedString("%d", s.Connection.Disconnected))
	output.Field("  Never connected", color.New(color.Faint).Sprintf("%d", s.Connection.NeverConnected))
	output.Field("  Pending", color.YellowString("%d", s.Connection.Pending))
	output.Field("  Total", color.New(color.Bold).Sprintf("%d", s.Connection.Total))
	printSection("Configuration sync")
	output.Field("  Synced", color.GreenString("%d", s.Config.Synced))
	output.Field("  Not synced", color.YellowString("%d", s.Config.NotSynced))
	output.Field("  Total", color.New(color.Bold).Sprintf("%d", s.Config.Total))
	fmt.Println()
}

func agentAdd(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("agent add", flag.ContinueOnError)
	name := fs.String("name", "", "Agent name (required)")
	ip := fs.String("ip", "any", "Agent IP or 'any'")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt
	if *name == "" {
		printErr(fmt.Errorf("--name is required"))
		return
	}
	a := api.NewAgentsAPI(managerClient)
	id, key, err := a.Add(*name, *ip)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(map[string]string{"id": id, "name": *name, "key": key})
		return
	}
	fmt.Printf("Agent registered: %s (ID: %s)\n\n", color.GreenString(*name), color.GreenString(id))
	output.Field("Enrollment key", key)
	fmt.Printf("\n%s\n", brandDim.Sprint("Deploy: /var/ossec/bin/agent-auth -m <manager_ip> -A "+*name))
}

func agentRemove(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("agent remove", flag.ContinueOnError)
	force := fs.Bool("f", false, "Skip confirmation")
	if err := fs.Parse(args); err != nil {
		return
	}
	rest := fs.Args()
	if len(rest) == 0 {
		printErr(fmt.Errorf("usage: agent remove <agent_id> [-f]"))
		return
	}
	agentID := rest[0]
	if !*force {
		fmt.Printf("Remove agent %s? This cannot be undone. [y/N]: ", color.YellowString(agentID))
		var confirm string
		fmt.Scanln(&confirm)
		if strings.ToLower(confirm) != "y" {
			fmt.Println("Aborted.")
			return
		}
	}
	a := api.NewAgentsAPI(managerClient)
	if err := a.Remove(agentID); err != nil {
		printErr(err)
		return
	}
	printOK(fmt.Sprintf("Agent %s removed", color.GreenString(agentID)))
}

func agentUpgrade(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: agent upgrade <agent_id> [--version V] [--no-watch]"))
		return
	}
	fs := flag.NewFlagSet("agent upgrade", flag.ContinueOnError)
	version := fs.String("version", "", "Target version (e.g. v4.9.0)")
	noWatch := fs.Bool("no-watch", false, "Fire and forget")
	if err := fs.Parse(args[1:]); err != nil {
		return
	}

	agentID := args[0]
	a := api.NewAgentsAPI(managerClient)
	tasks, err := a.Upgrade(agentID, *version)
	if err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "already up to date") || strings.HasPrefix(msg, "newer than repo") {
			fmt.Printf("%s agent %s — %s\n", color.YellowString("note:"), color.GreenString(agentID), msg)
			return
		}
		printErr(err)
		return
	}
	if len(tasks) == 0 {
		printWarn("no tasks returned by the API")
		return
	}

	target := *version
	if target == "" {
		target = "latest"
	}
	fmt.Printf("Upgrade to %s requested for agent %s\n\n",
		color.CyanString(target), color.GreenString(agentID))

	if *noWatch {
		for _, t := range tasks {
			fmt.Printf("  Task #%d started\n", t.TaskID)
		}
		return
	}

	agentIDs := make([]string, len(tasks))
	for i, t := range tasks {
		agentIDs[i] = t.Agent
	}

	dim := color.New(color.Faint)
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spin := 0
	for poll := 0; poll < 120; poll++ {
		statuses, err := a.TasksStatus(agentIDs)
		if err != nil {
			printErr(fmt.Errorf("polling tasks: %v", err))
			return
		}
		done, failed := 0, 0
		fmt.Print("\033[H\033[2J")
		fmt.Printf("Upgrade to %s — agent %s\n\n", color.CyanString(target), color.GreenString(agentID))
		for _, s := range statuses {
			var badge string
			switch s.Status {
			case "Done":
				badge = color.GreenString("✓ Done      ")
				done++
			case "Failed":
				badge = color.RedString("✗ Failed    ")
				failed++
			case "Cancelled":
				badge = color.YellowString("⊘ Cancelled ")
				failed++
			default:
				badge = color.YellowString(spinner[spin%len(spinner)] + " " + s.Status)
			}
			line := fmt.Sprintf("  Task #%d  %s", s.TaskID, badge)
			if s.ErrorMessage != "" {
				line += "  " + dim.Sprint(s.ErrorMessage)
			} else if s.Data != "" {
				line += "  " + dim.Sprint(s.Data)
			}
			line += dim.Sprintf("  (updated %s)", s.LastUpdateTime)
			fmt.Println(line)
		}
		if done+failed == len(statuses) {
			fmt.Println()
			if failed > 0 {
				fmt.Printf("%s upgrade finished with %d failure(s)\n", color.RedString("✗"), failed)
			} else {
				printOK("all tasks completed successfully")
			}
			return
		}
		spin++
		time.Sleep(5 * time.Second)
	}
	printWarn(fmt.Sprintf("polling timed out — check manually: agent get %s", agentID))
}

func agentGroups(_ []string) {
	if !needsManager() {
		return
	}
	a := api.NewAgentsAPI(managerClient)
	groups, err := a.Groups()
	if err != nil {
		printErr(err)
		return
	}
	t := output.NewTable("NAME", "AGENTS")
	for _, g := range groups {
		t.Row(g.Name, fmt.Sprintf("%d", g.Count))
	}
	t.Flush()
}
