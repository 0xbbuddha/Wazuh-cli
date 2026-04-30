package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newVulnCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vuln",
		Short: "Vulnerability detection results",
		Aliases: []string{"v"},
	}

	var (
		severity string
		limit    int
	)
	listCmd := &cobra.Command{
		Use:   "list <agent_id>",
		Short: "List detected vulnerabilities for an agent",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			v := api.NewVulnAPI(managerClient)
			vulns, total, err := v.List(args[0], severity, limit)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(vulns)
				return
			}
			fmt.Printf("Showing %d of %d vulnerabilities\n\n", len(vulns), total)
			t := output.NewTable("CVE", "SEVERITY", "PACKAGE", "VERSION", "TITLE")
			for _, vv := range vulns {
				title := vv.Title
				if len(title) > 60 {
					title = title[:57] + "..."
				}
				t.Row(vv.CVE, output.ColorSeverity(vv.Severity), vv.Name, vv.Version, title)
			}
			t.Flush()
		},
	}
	listCmd.Flags().StringVar(&severity, "severity", "", "Filter by severity: critical, high, medium, low")
	listCmd.Flags().IntVar(&limit, "limit", 500, "Maximum number of results")
	cmd.AddCommand(listCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "summary <agent_id>",
		Short: "Show vulnerability summary grouped by severity",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			v := api.NewVulnAPI(managerClient)
			summary, err := v.Summary(args[0], "severity")
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(summary)
				return
			}
			for k, val := range summary {
				fmt.Printf("%-12s %s\n", k+":", output.ColorSeverity(fmt.Sprintf("%v", val)))
			}
		},
	})

	return cmd
}
