package cmd

import (
	"fmt"
	"strings"

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

	cmd.AddCommand(listCmd, getCmd, restartCmd, summaryCmd, groupsCmd)
	return cmd
}
