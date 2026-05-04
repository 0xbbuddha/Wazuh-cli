package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "agent",
		Short:   "Manage Wazuh agents",
		Aliases: []string{"a"},
	}

	// agent list
	var (
		status string
		group  string
		limit  int
	)
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all agents",
		Run: func(cmd *cobra.Command, args []string) {
			a := api.NewAgentsAPI(managerClient)
			agents, total, err := a.List(status, group, limit)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(agents)
				return
			}
			fmt.Printf("Showing %d of %d agents\n\n", len(agents), total)
			t := output.NewTable("ID", "NAME", "STATUS", "IP", "OS", "VERSION", "GROUP")
			for _, ag := range agents {
				t.Row(ag.ID, ag.Name, output.ColorStatus(ag.Status), ag.IP,
					ag.Os.Name+" "+ag.Os.Version, ag.Version, strings.Join(ag.Group, ","))
			}
			t.Flush()
		},
	}
	listCmd.Flags().StringVar(&status, "status", "", "Filter by status: active, disconnected, never_connected, pending")
	listCmd.Flags().StringVar(&group, "group", "", "Filter by group name")
	listCmd.Flags().IntVar(&limit, "limit", 500, "Maximum number of results")

	// agent get
	getCmd := &cobra.Command{
		Use:   "get <agent_id>",
		Short: "Get detailed info for an agent",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			a := api.NewAgentsAPI(managerClient)
			ag, err := a.Get(args[0])
			if err != nil {
				die(err)
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
		},
	}

	// agent restart
	restartCmd := &cobra.Command{
		Use:   "restart <agent_id>",
		Short: "Restart an agent",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			a := api.NewAgentsAPI(managerClient)
			if err := a.Restart(args[0]); err != nil {
				die(err)
			}
			fmt.Printf("Agent %s restart requested.\n", color.GreenString(args[0]))
		},
	}

	// agent summary
	summaryCmd := &cobra.Command{
		Use:   "summary",
		Short: "Show agent status summary",
		Run: func(cmd *cobra.Command, args []string) {
			a := api.NewAgentsAPI(managerClient)
			s, err := a.Summary()
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(s)
				return
			}
			fmt.Println("Connection status:")
			output.Field("  Active", fmt.Sprintf("%d", s.Connection.Active))
			output.Field("  Disconnected", fmt.Sprintf("%d", s.Connection.Disconnected))
			output.Field("  Never connected", fmt.Sprintf("%d", s.Connection.NeverConnected))
			output.Field("  Pending", fmt.Sprintf("%d", s.Connection.Pending))
			output.Field("  Total", fmt.Sprintf("%d", s.Connection.Total))
			fmt.Println("Configuration sync:")
			output.Field("  Synced", fmt.Sprintf("%d", s.Config.Synced))
			output.Field("  Not synced", fmt.Sprintf("%d", s.Config.NotSynced))
			output.Field("  Total", fmt.Sprintf("%d", s.Config.Total))
		},
	}

	// agent groups
	groupsCmd := &cobra.Command{
		Use:   "groups",
		Short: "List agent groups",
		Run: func(cmd *cobra.Command, args []string) {
			a := api.NewAgentsAPI(managerClient)
			groups, err := a.Groups()
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(groups)
				return
			}
			t := output.NewTable("NAME", "AGENTS")
			for _, g := range groups {
				t.Row(g.Name, fmt.Sprintf("%d", g.Count))
			}
			t.Flush()
		},
	}

	// agent add
	var agentName, agentIP string
	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Register a new agent",
		Run: func(cmd *cobra.Command, args []string) {
			if agentName == "" {
				die(fmt.Errorf("--name is required"))
			}
			a := api.NewAgentsAPI(managerClient)
			id, key, err := a.Add(agentName, agentIP)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(map[string]string{"id": id, "name": agentName, "key": key})
				return
			}
			fmt.Printf("Agent registered: %s (ID: %s)\n\n", color.GreenString(agentName), color.GreenString(id))
			output.Field("Enrollment key", key)
			fmt.Printf("\n%s\n", color.New(color.Faint).Sprint("Deploy: /var/ossec/bin/agent-auth -m <manager_ip> -A "+agentName))
		},
	}
	addCmd.Flags().StringVar(&agentName, "name", "", "Agent name (required)")
	addCmd.Flags().StringVar(&agentIP, "ip", "any", "Agent IP or 'any'")

	// agent remove
	var forceRemove bool
	removeCmd := &cobra.Command{
		Use:   "remove <agent_id>",
		Short: "Remove an agent",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if !forceRemove {
				fmt.Printf("Remove agent %s? This cannot be undone. [y/N]: ", color.YellowString(args[0]))
				var confirm string
				fmt.Scanln(&confirm)
				if strings.ToLower(confirm) != "y" {
					fmt.Println("Aborted.")
					return
				}
			}
			a := api.NewAgentsAPI(managerClient)
			if err := a.Remove(args[0]); err != nil {
				die(err)
			}
			fmt.Printf("Agent %s removed.\n", color.GreenString(args[0]))
		},
	}
	removeCmd.Flags().BoolVarP(&forceRemove, "force", "f", false, "Skip confirmation prompt")

	// agent upgrade
	var upgradeVersion string
	var noWatch bool
	upgradeCmd := &cobra.Command{
		Use:   "upgrade <agent_id>",
		Short: "Upgrade agent to latest or a specific version",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			a := api.NewAgentsAPI(managerClient)
			tasks, err := a.Upgrade(args[0], upgradeVersion)
			if err != nil {
				msg := err.Error()
				if strings.HasPrefix(msg, "already up to date") || strings.HasPrefix(msg, "newer than repo") {
					fmt.Printf("%s agent %s — %s\n",
						color.YellowString("note:"),
						color.GreenString(args[0]),
						msg)
					return
				}
				die(err)
			}
			if len(tasks) == 0 {
				fmt.Println(color.YellowString("warning:") + " no tasks returned by the API")
				return
			}

			target := upgradeVersion
			if target == "" {
				target = "latest"
			}
			fmt.Printf("Upgrade to %s requested for agent %s\n\n",
				color.CyanString(target), color.GreenString(args[0]))

			if noWatch {
				for _, t := range tasks {
					fmt.Printf("  Task #%d started\n", t.TaskID)
				}
				return
			}

			// Collect agent IDs from upgrade tasks
			agentIDs := make([]string, len(tasks))
			for i, t := range tasks {
				agentIDs[i] = t.Agent
			}

			// Poll until all tasks reach a terminal state
			dim := color.New(color.Faint)
			spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			spin := 0
			const maxPolls = 120 // 10 minutes max
			for poll := 0; poll < maxPolls; poll++ {
				statuses, err := a.TasksStatus(agentIDs)
				if err != nil {
					fmt.Printf("\r%s polling tasks: %v\n", color.RedString("error"), err)
					return
				}

				// Render current state
				done := 0
				failed := 0
				fmt.Print("\033[H\033[2J") // clear screen
				fmt.Printf("Upgrade to %s — agent %s\n\n",
					color.CyanString(target), color.GreenString(args[0]))
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
						badge = color.YellowString(spinner[spin%len(spinner)]+" "+s.Status)
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
						fmt.Printf("%s all tasks completed successfully\n", color.GreenString("✓"))
					}
					return
				}

				spin++
				time.Sleep(5 * time.Second)
			}
			fmt.Printf("\n%s polling timed out — check manually: wazuh-cli agent get %s\n",
				color.YellowString("warning:"), args[0])
		},
	}
	upgradeCmd.Flags().StringVar(&upgradeVersion, "version", "", "Target version (e.g. v4.9.0), default: latest")
	upgradeCmd.Flags().BoolVar(&noWatch, "no-watch", false, "Fire and forget — do not poll for progress")

	cmd.AddCommand(listCmd, getCmd, restartCmd, summaryCmd, groupsCmd, addCmd, removeCmd, upgradeCmd)
	return cmd
}
