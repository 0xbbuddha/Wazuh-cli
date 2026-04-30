package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newAlertsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "alerts",
		Short:   "Query alerts from the Wazuh Indexer (OpenSearch)",
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
		limit    int
		level    int
		agentID  string
		watch    bool
		interval int
	)
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List recent alerts",
		Run: func(cmd *cobra.Command, args []string) {
			if watch {
				runWatch(limit, level, agentID, interval)
				return
			}
			printAlerts(limit, level, agentID)
		},
	}
	listCmd.Flags().IntVar(&limit, "limit", 20, "Number of alerts to show")
	listCmd.Flags().IntVar(&level, "level", 0, "Minimum alert level (0 = all)")
	listCmd.Flags().StringVar(&agentID, "agent", "", "Filter by agent ID")
	listCmd.Flags().BoolVar(&watch, "watch", false, "Refresh alerts continuously")
	listCmd.Flags().IntVar(&interval, "interval", 5, "Refresh interval in seconds (used with --watch)")
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

func printAlerts(limit, level int, agentID string) {
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
}

func runWatch(limit, level int, agentID string, interval int) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	dim := color.New(color.Faint)
	bold := color.New(color.Bold)

	for {
		clearScreen()
		now := time.Now().Format("15:04:05")
		bold.Printf("wazuh-cli alerts list --watch")
		fmt.Printf("   ")
		dim.Printf("updated %s · every %ds · Ctrl+C to stop\n\n", now, interval)

		printAlerts(limit, level, agentID)

		select {
		case <-sig:
			fmt.Println()
			return
		case <-time.After(time.Duration(interval) * time.Second):
		}
	}
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}
