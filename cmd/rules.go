package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Browse detection rules",
		Aliases: []string{"r"},
	}

	var (
		level int
		group string
		limit int
	)
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List rules",
		Run: func(cmd *cobra.Command, args []string) {
			r := api.NewRulesAPI(managerClient)
			rules, total, err := r.List(level, group, limit)
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(rules)
				return
			}
			fmt.Printf("Showing %d of %d rules\n\n", len(rules), total)
			t := output.NewTable("ID", "LEVEL", "GROUPS", "DESCRIPTION")
			for _, rule := range rules {
				t.Row(fmt.Sprintf("%d", rule.ID), output.ColorLevel(rule.Level),
					strings.Join(rule.Groups, ","), output.Truncate(rule.Description, 60))
			}
			t.Flush()
		},
	}
	listCmd.Flags().IntVar(&level, "level", 0, "Filter by minimum rule level (0 = no filter)")
	listCmd.Flags().StringVar(&group, "group", "", "Filter by rule group")
	listCmd.Flags().IntVar(&limit, "limit", 500, "Maximum number of results")
	cmd.AddCommand(listCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "get <rule_id>",
		Short: "Get details for a specific rule",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			r := api.NewRulesAPI(managerClient)
			rule, err := r.Get(args[0])
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(rule)
				return
			}
			output.Field("ID", fmt.Sprintf("%d", rule.ID))
			output.Field("Level", output.ColorLevel(rule.Level))
			output.Field("Description", rule.Description)
			output.Field("Groups", strings.Join(rule.Groups, ", "))
			output.Field("File", rule.Filename)
			output.Field("Status", rule.Status)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "groups",
		Short: "List all rule groups",
		Run: func(cmd *cobra.Command, args []string) {
			r := api.NewRulesAPI(managerClient)
			groups, err := r.Groups()
			if err != nil {
				die(err)
			}
			if output.Format == "json" {
				output.JSON(groups)
				return
			}
			for _, g := range groups {
				fmt.Println(g)
			}
		},
	})

	return cmd
}
