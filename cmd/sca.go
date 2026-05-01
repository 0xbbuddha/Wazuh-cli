package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newSCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sca",
		Short: "Security Configuration Assessment results",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list <agent_id>",
		Short: "List SCA policies and their scores for an agent",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s := api.NewSCAAPI(managerClient)
			policies, err := s.List(args[0])
			if err != nil {
				die(err)
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
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "checks <agent_id> <policy_id>",
		Short: "Show detailed check results for a policy",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			s := api.NewSCAAPI(managerClient)
			checks, total, err := s.Checks(args[0], args[1])
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(checks)
				return
			}
			fmt.Printf("Showing %d of %d checks\n\n", len(checks), total)
			t := output.NewTable("ID", "RESULT", "TITLE")
			for _, ch := range checks {
				t.Row(fmt.Sprintf("%d", ch.ID), output.ColorResult(ch.Result), output.Truncate(ch.Title, 60))
			}
			t.Flush()
		},
	})

	return cmd
}
