package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

type arAction struct {
	command     string
	needsIP     bool
	description string
}

// arActions maps user-friendly names to Wazuh active response commands.
// Commands ending in 0 = add/block, 1 = remove/unblock.
var arActions = map[string]arAction{
	"restart":    {"restart-wazuh0", false, "Restart the Wazuh agent service"},
	"block-ip":   {"firewall-drop0", true, "Block an IP address via iptables/firewall"},
	"unblock-ip": {"firewall-drop1", true, "Remove an IP block"},
	"host-deny":  {"host-deny0", true, "Add IP to /etc/hosts.deny"},
	"host-allow": {"host-deny1", true, "Remove IP from /etc/hosts.deny"},
	"route-null": {"route-null0", true, "Add a null route for an IP (traffic black-hole)"},
}

var arActionOrder = []string{"restart", "block-ip", "unblock-ip", "host-deny", "host-allow", "route-null"}

func newARCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ar",
		Short:   "Active response — trigger actions on agents",
		Aliases: []string{"active-response"},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List available active response actions",
		Run: func(cmd *cobra.Command, args []string) {
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
		},
	})

	var force bool
	runCmd := &cobra.Command{
		Use:   "run <agent_id|all> <action> [<ip>]",
		Short: "Run an active response action on an agent",
		Example: `  wazuh-cli ar run 039 restart
  wazuh-cli ar run 039 block-ip 1.2.3.4
  wazuh-cli ar run 039 unblock-ip 1.2.3.4
  wazuh-cli ar run all block-ip 1.2.3.4 --force`,
		Args: cobra.RangeArgs(2, 3),
		Run: func(cmd *cobra.Command, args []string) {
			agentID := args[0]
			actionName := args[1]

			action, ok := arActions[actionName]
			if !ok {
				die(fmt.Errorf("unknown action %q\n\nRun 'wazuh-cli ar list' to see available actions", actionName))
			}

			var ip string
			if action.needsIP {
				if len(args) < 3 {
					die(fmt.Errorf("action %q requires an IP address\n\nExample: wazuh-cli ar run %s %s 1.2.3.4",
						actionName, agentID, actionName))
				}
				ip = args[2]
			}

			// Require confirmation for mass operations.
			if agentID == "all" && !force {
				fmt.Printf("%s This will run %q on ALL agents.\n",
					color.YellowString("Warning:"), actionName)
				fmt.Print("Continue? [y/N] ")
				var answer string
				fmt.Scanln(&answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Println("Aborted.")
					return
				}
			}

			// Wazuh v4 passes IP-based data via alert.data.srcip.
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
				die(err)
			}

			if result.TotalFailed > 0 {
				color.New(color.FgRed, color.Bold).Printf("Failed ")
				fmt.Printf("(%d affected, %d failed)\n", result.TotalAffected, result.TotalFailed)
				for _, f := range result.FailedItems {
					fmt.Printf("  agents %v — [%d] %s\n",
						f.IDs, f.Error.Code, f.Error.Message)
				}
				return
			}

			target := "agent " + agentID
			if agentID == "all" {
				target = fmt.Sprintf("%d agent(s)", result.TotalAffected)
			}
			color.New(color.FgGreen, color.Bold).Printf("OK ")
			fmt.Printf("%s executed on %s\n", actionName, target)
		},
	}
	runCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation for mass operations")
	cmd.AddCommand(runCmd)

	return cmd
}
