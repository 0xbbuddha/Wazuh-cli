package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newManagerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "manager",
		Short:   "Manager information and status",
		Aliases: []string{"m"},
	}

	// manager info
	cmd.AddCommand(&cobra.Command{
		Use:   "info",
		Short: "Show manager version and build info",
		Run: func(cmd *cobra.Command, args []string) {
			m := api.NewManagerAPI(managerClient)
			info, err := m.Info()
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(info)
				return
			}
			output.Field("Version", info.Version)
			output.Field("Type", info.Type)
			output.Field("Path", info.Path)
			output.Field("Compiled", info.Compilation)
			output.Field("Max agents", info.MaxAgents)
			output.Field("OpenSSL", info.OpenSSL)
		},
	})

	// manager status
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show status of all Wazuh daemons",
		Run: func(cmd *cobra.Command, args []string) {
			m := api.NewManagerAPI(managerClient)
			status, err := m.Status()
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(status)
				return
			}
			daemons := make([]string, 0, len(status))
			for k := range status {
				daemons = append(daemons, k)
			}
			sort.Strings(daemons)
			t := output.NewTable("DAEMON", "STATUS")
			for _, d := range daemons {
				t.Row(d, output.ColorDaemon(status[d]))
			}
			t.Flush()
		},
	})

	// manager logs
	var lines int
	logsCmd := &cobra.Command{
		Use:   "logs",
		Short: "Show recent manager logs",
		Run: func(cmd *cobra.Command, args []string) {
			m := api.NewManagerAPI(managerClient)
			logs, err := m.Logs(lines)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(logs)
				return
			}
			t := output.NewTable("TIMESTAMP", "LEVEL", "TAG", "DESCRIPTION")
			for _, l := range logs {
				t.Row(l.Timestamp, output.ColorDaemon(l.Level), l.Tag, l.Description)
			}
			t.Flush()
			fmt.Printf("\n%d log entries shown.\n", len(logs))
		},
	}
	logsCmd.Flags().IntVar(&lines, "lines", 20, "Number of log entries to show")
	cmd.AddCommand(logsCmd)

	return cmd
}
