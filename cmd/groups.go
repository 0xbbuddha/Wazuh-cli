package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newGroupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "groups",
		Short:   "Manage agent groups",
		Aliases: []string{"group"},
	}

	// ── list ──────────────────────────────────────────────────────────────────
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all groups",
		Run: func(cmd *cobra.Command, args []string) {
			groups, err := api.NewGroupsAPI(managerClient).List()
			if err != nil {
				die(err)
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
		},
	}

	// ── agents <group> ────────────────────────────────────────────────────────
	agentsCmd := &cobra.Command{
		Use:   "agents <group>",
		Short: "List agents belonging to a group",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			agents, total, err := api.NewGroupsAPI(managerClient).Agents(args[0], 500)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(agents)
				return
			}
			fmt.Printf("Group: %s  (%d agents)\n\n", args[0], total)
			t := output.NewTable("ID", "NAME", "STATUS", "IP", "OS", "VERSION")
			for _, a := range agents {
				t.Row(a.ID, a.Name, output.ColorStatus(a.Status), a.IP,
					strings.TrimSpace(a.Os.Name+" "+a.Os.Version), a.Version)
			}
			t.Flush()
		},
	}

	// ── create <name> ─────────────────────────────────────────────────────────
	createCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new group",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := api.NewGroupsAPI(managerClient).Create(args[0]); err != nil {
				die(err)
			}
			brandGreen.Printf("✓  Group %q created\n", args[0])
		},
	}

	// ── delete <name> ─────────────────────────────────────────────────────────
	var force bool
	deleteCmd := &cobra.Command{
		Use:   "delete <group>",
		Short: "Delete a group",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if !force {
				fmt.Printf("Delete group %q? [y/N] ", args[0])
				var ans string
				fmt.Scanln(&ans)
				if strings.ToLower(ans) != "y" {
					fmt.Println("Aborted.")
					return
				}
			}
			if err := api.NewGroupsAPI(managerClient).Delete(args[0]); err != nil {
				die(err)
			}
			brandGreen.Printf("✓  Group %q deleted\n", args[0])
		},
	}
	deleteCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

	// ── assign <agent_id> <group> ─────────────────────────────────────────────
	assignCmd := &cobra.Command{
		Use:   "assign <agent_id> <group>",
		Short: "Assign an agent to a group",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if err := api.NewGroupsAPI(managerClient).Assign(args[0], args[1]); err != nil {
				die(err)
			}
			brandGreen.Printf("✓  Agent %s assigned to group %q\n", args[0], args[1])
		},
	}

	// ── unassign <agent_id> <group> ───────────────────────────────────────────
	unassignCmd := &cobra.Command{
		Use:   "unassign <agent_id> <group>",
		Short: "Remove an agent from a group",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if err := api.NewGroupsAPI(managerClient).Unassign(args[0], args[1]); err != nil {
				die(err)
			}
			brandGreen.Printf("✓  Agent %s removed from group %q\n", args[0], args[1])
		},
	}

	cmd.AddCommand(listCmd, agentsCmd, createCmd, deleteCmd, assignCmd, unassignCmd)
	return cmd
}
