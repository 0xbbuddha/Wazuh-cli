package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleGroups(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"groups"})
		return
	}
	switch args[0] {
	case "list":
		groupsList(args[1:])
	case "agents":
		groupsAgents(args[1:])
	case "create":
		groupsCreate(args[1:])
	case "delete":
		groupsDelete(args[1:])
	case "assign":
		groupsAssign(args[1:])
	case "unassign":
		groupsUnassign(args[1:])
	case "config":
		groupsConfig(args[1:])
	case "config-edit":
		groupsConfigEdit(args[1:])
	default:
		printUnknownSub("groups", args[0])
	}
}

func groupsList(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("groups list", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt

	groups, err := api.NewGroupsAPI(managerClient).List()
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(groups)
		return
	}
	t := output.NewTable("GROUP", "AGENTS", "CONFIG HASH")
	for _, g := range groups {
		t.Row(g.Name, fmt.Sprintf("%d", g.Count), g.Config)
	}
	t.Flush()
}

func groupsAgents(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: groups agents <group_name>"))
		return
	}
	fs := flag.NewFlagSet("groups agents", flag.ContinueOnError)
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt
	groupName := args[0]

	agents, total, err := api.NewGroupsAPI(managerClient).Agents(groupName, 500)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(agents)
		return
	}
	fmt.Printf("Group: %s  (%d agents)\n\n", groupName, total)
	t := output.NewTable("ID", "NAME", "STATUS", "IP", "OS", "VERSION")
	for _, a := range agents {
		t.Row(a.ID, a.Name, output.ColorStatus(a.Status), a.IP,
			strings.TrimSpace(a.Os.Name+" "+a.Os.Version), a.Version)
	}
	t.Flush()
}

func groupsCreate(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: groups create <group_name>"))
		return
	}
	if err := api.NewGroupsAPI(managerClient).Create(args[0]); err != nil {
		printErr(err)
		return
	}
	printOK(fmt.Sprintf("Group %q created", args[0]))
}

func groupsDelete(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: groups delete <group_name> [-f]"))
		return
	}
	fs := flag.NewFlagSet("groups delete", flag.ContinueOnError)
	force := fs.Bool("f", false, "Skip confirmation")
	groupName := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	if !*force {
		if !promptConfirm(fmt.Sprintf("Delete group %q?", groupName)) {
			fmt.Println("Aborted.")
			return
		}
	}
	if err := api.NewGroupsAPI(managerClient).Delete(groupName); err != nil {
		printErr(err)
		return
	}
	printOK(fmt.Sprintf("Group %q deleted", groupName))
}

func groupsAssign(args []string) {
	if !needsManager() {
		return
	}
	if len(args) < 2 {
		printErr(fmt.Errorf("usage: groups assign <agent_id> <group_name>"))
		return
	}
	if err := api.NewGroupsAPI(managerClient).Assign(args[0], args[1]); err != nil {
		printErr(err)
		return
	}
	printOK(fmt.Sprintf("Agent %s assigned to group %q", args[0], args[1]))
}

func groupsUnassign(args []string) {
	if !needsManager() {
		return
	}
	if len(args) < 2 {
		printErr(fmt.Errorf("usage: groups unassign <agent_id> <group_name>"))
		return
	}
	if err := api.NewGroupsAPI(managerClient).Unassign(args[0], args[1]); err != nil {
		printErr(err)
		return
	}
	printOK(fmt.Sprintf("Agent %s removed from group %q", args[0], args[1]))
}

func groupsConfig(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: groups config <group_name>"))
		return
	}
	xml, err := api.NewGroupsAPI(managerClient).GetConfig(args[0])
	if err != nil {
		printErr(err)
		return
	}
	fmt.Println(xml)
}

func groupsConfigEdit(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: groups config-edit <group_name>"))
		return
	}
	groupName := args[0]
	gapi := api.NewGroupsAPI(managerClient)

	// Fetch current config
	original, err := gapi.GetConfig(groupName)
	if err != nil {
		printErr(err)
		return
	}

	// Write to temp file
	tmp, err := os.CreateTemp("", "wazuh-agent-conf-*.xml")
	if err != nil {
		printErr(fmt.Errorf("cannot create temp file: %w", err))
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.WriteString(original); err != nil {
		tmp.Close()
		printErr(fmt.Errorf("cannot write temp file: %w", err))
		return
	}
	tmp.Close()

	// Open in $EDITOR (fallback to vi)
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	cmd := exec.Command(editor, tmpPath)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		printErr(fmt.Errorf("editor exited with error: %w", err))
		return
	}

	// Read back
	updated, err := os.ReadFile(tmpPath)
	if err != nil {
		printErr(fmt.Errorf("cannot read temp file: %w", err))
		return
	}

	// Skip upload if nothing changed
	if string(updated) == original {
		printWarn("No changes detected - config not updated.")
		return
	}

	if err := gapi.PutConfig(groupName, string(updated)); err != nil {
		printErr(fmt.Errorf("upload failed: %w", err))
		return
	}
	printOK(fmt.Sprintf("agent.conf for group %q updated successfully", groupName))
}
