package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newAlertsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Query alerts from the Wazuh Indexer (OpenSearch)",
		Aliases: []string{"al"},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if indexerClient == nil {
				fmt.Fprintln(os.Stderr, color.RedString("Error:")+" indexer.url is not configured in config.toml")
				os.Exit(1)
			}
			output.Format = outputFormat
			return nil
		},
	}

	var (
		limit   int
		level   int
		agentID string
	)
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List recent alerts",
		Run: func(cmd *cobra.Command, args []string) {
			alerts, total, err := indexerClient.Alerts(limit, level, agentID)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(alerts)
				return
			}
			fmt.Printf("Showing %d of %d alerts\n\n", len(alerts), total)
			t := output.NewTable("TIMESTAMP", "LVL", "AGENT", "RULE", "DESCRIPTION")
			for _, a := range alerts {
				t.Row(a.Timestamp,
					output.ColorLevel(a.Rule.Level),
					a.Agent.Name,
					a.Rule.ID,
					a.Rule.Description)
			}
			t.Flush()
		},
	}
	listCmd.Flags().IntVar(&limit, "limit", 20, "Number of alerts to show")
	listCmd.Flags().IntVar(&level, "level", 0, "Minimum alert level (0 = all)")
	listCmd.Flags().StringVar(&agentID, "agent", "", "Filter by agent ID")
	cmd.AddCommand(listCmd)

	var searchLimit int
	searchCmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Full-text search across alert logs and descriptions",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			alerts, total, err := indexerClient.Search(args[0], searchLimit)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(alerts)
				return
			}
			fmt.Printf("Showing %d of %d results for %q\n\n", len(alerts), total, args[0])
			t := output.NewTable("TIMESTAMP", "LVL", "AGENT", "RULE", "DESCRIPTION")
			for _, a := range alerts {
				t.Row(a.Timestamp,
					output.ColorLevel(a.Rule.Level),
					a.Agent.Name,
					a.Rule.ID,
					a.Rule.Description)
			}
			t.Flush()
		},
	}
	searchCmd.Flags().IntVar(&searchLimit, "limit", 20, "Number of results to show")
	cmd.AddCommand(searchCmd)

	return cmd
}
