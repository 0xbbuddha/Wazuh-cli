package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleRules(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"rules"})
		return
	}
	switch args[0] {
	case "list":
		rulesList(args[1:])
	case "get":
		rulesGet(args[1:])
	case "groups":
		rulesGroups()
	default:
		printUnknownSub("rules", args[0])
	}
}

func rulesList(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("rules list", flag.ContinueOnError)
	level := fs.Int("level", 0, "Filter by minimum rule level (0 = no filter)")
	group := fs.String("group", "", "Filter by rule group")
	limit := fs.Int("limit", 20, "Results per page")
	page := fs.Int("page", 1, "Page number (starts at 1)")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt
	if *page < 1 {
		*page = 1
	}
	offset := (*page - 1) * *limit

	r := api.NewRulesAPI(managerClient)
	rules, total, err := r.List(*level, *group, *limit, offset)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(rules)
		return
	}
	totalPages := (total + *limit - 1) / *limit
	output.ShowCount(len(rules), total, fmt.Sprintf("rules - page %d/%d", *page, totalPages))
	t := output.NewTable("ID", "LEVEL", "GROUPS", "DESCRIPTION")
	for _, rule := range rules {
		t.Row(fmt.Sprintf("%d", rule.ID), output.ColorLevel(rule.Level),
			strings.Join(rule.Groups, ","), output.Truncate(rule.Description, 60))
	}
	t.Flush()
	if totalPages > 1 {
		color.New(color.Faint).Printf("\n  --page %d/%d  (--limit %d to change page size)\n\n", *page, totalPages, *limit)
	}
}

func rulesGet(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: rules get <rule_id>"))
		return
	}
	r := api.NewRulesAPI(managerClient)
	rule, err := r.Get(args[0])
	if err != nil {
		printErr(err)
		return
	}
	output.Field("ID", fmt.Sprintf("%d", rule.ID))
	output.Field("Level", output.ColorLevel(rule.Level))
	output.Field("Description", rule.Description)
	output.Field("Groups", strings.Join(rule.Groups, ", "))
	output.Field("File", rule.Filename)
	output.Field("Status", rule.Status)
}

func rulesGroups() {
	if !needsManager() {
		return
	}
	r := api.NewRulesAPI(managerClient)
	groups, err := r.Groups()
	if err != nil {
		printErr(err)
		return
	}
	for _, g := range groups {
		fmt.Println(g)
	}
}
