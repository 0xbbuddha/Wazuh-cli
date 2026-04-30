package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Cluster status and nodes",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show whether clustering is enabled and running",
		Run: func(cmd *cobra.Command, args []string) {
			cl := api.NewClusterAPI(managerClient)
			s, err := cl.Status()
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(s)
				return
			}
			output.Field("Enabled", s.Enabled)
			output.Field("Running", s.Running)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "nodes",
		Short: "List cluster nodes",
		Run: func(cmd *cobra.Command, args []string) {
			cl := api.NewClusterAPI(managerClient)
			nodes, err := cl.Nodes()
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(nodes)
				return
			}
			t := output.NewTable("NAME", "TYPE", "IP", "VERSION", "STATUS")
			for _, n := range nodes {
				t.Row(n.Name, n.Type, n.IP, n.Version, n.Status)
			}
			t.Flush()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "health",
		Short: "Show cluster health check",
		Run: func(cmd *cobra.Command, args []string) {
			cl := api.NewClusterAPI(managerClient)
			h, err := cl.Health()
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(h)
				return
			}
			fmt.Printf("%d nodes in cluster\n\n", len(h.Nodes))
			t := output.NewTable("NODE", "TYPE", "IP", "VERSION")
			for name, n := range h.Nodes {
				t.Row(name, n.Info.Type, n.Info.IP, n.Info.Version)
			}
			t.Flush()
		},
	})

	return cmd
}
