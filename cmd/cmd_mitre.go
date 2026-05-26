package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleMitre(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"mitre"})
		return
	}
	switch args[0] {
	case "techniques":
		mitreTechniques(args[1:])
	case "tactics":
		mitreTactics(args[1:])
	case "groups":
		mitreGroups(args[1:])
	case "software":
		mitreSoftware(args[1:])
	case "show":
		mitreShow(args[1:])
	default:
		printUnknownSub("mitre", args[0])
	}
}

func mitreTechniques(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("mitre techniques", flag.ContinueOnError)
	search := fs.String("search", "", "Filter by name or ID")
	tactic := fs.String("tactic", "", "Filter by tactic (e.g. execution, persistence)")
	limit := fs.Int("limit", 30, "Results per page")
	page := fs.Int("page", 1, "Page number")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt
	offset := (*page - 1) * *limit

	m := api.NewMitreAPI(managerClient)
	techs, total, err := m.Techniques(*search, *tactic, *limit, offset)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(techs)
		return
	}

	totalPages := (total + *limit - 1) / *limit
	if totalPages == 0 {
		totalPages = 1
	}
	output.ShowCount(len(techs), total, fmt.Sprintf("techniques - page %d/%d", *page, totalPages))

	t := output.NewTable("ID", "NAME", "TACTICS", "PLATFORMS")
	for _, tech := range techs {
		t.Row(
			color.CyanString(tech.ID),
			output.Truncate(tech.Name, 40),
			output.Dim(output.Truncate(strings.Join(tech.Tactics, ", "), 35)),
			output.Dim(output.Truncate(strings.Join(tech.Platforms, ", "), 30)),
		)
	}
	t.Flush()

	if *page < totalPages {
		color.New(color.Faint).Printf("\n  --page %d/%d  (--limit %d to change page size)\n\n", *page, totalPages, *limit)
	}
}

func mitreTactics(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("mitre tactics", flag.ContinueOnError)
	search := fs.String("search", "", "Filter by name")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt

	m := api.NewMitreAPI(managerClient)
	tactics, total, err := m.Tactics(*search, 100, 0)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(tactics)
		return
	}

	output.ShowCount(len(tactics), total, "tactics")
	t := output.NewTable("ID", "NAME")
	for _, tac := range tactics {
		t.Row(color.CyanString(tac.ID), tac.Name)
	}
	t.Flush()
}

func mitreGroups(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("mitre groups", flag.ContinueOnError)
	search := fs.String("search", "", "Filter by group name or alias")
	limit := fs.Int("limit", 30, "Results per page")
	page := fs.Int("page", 1, "Page number")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt
	offset := (*page - 1) * *limit

	m := api.NewMitreAPI(managerClient)
	groups, total, err := m.Groups(*search, *limit, offset)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(groups)
		return
	}

	totalPages := (total + *limit - 1) / *limit
	if totalPages == 0 {
		totalPages = 1
	}
	output.ShowCount(len(groups), total, fmt.Sprintf("threat groups - page %d/%d", *page, totalPages))

	t := output.NewTable("ID", "NAME", "ALIASES", "TECHNIQUES")
	for _, g := range groups {
		aliases := output.Truncate(strings.Join(g.Aliases, ", "), 30)
		t.Row(
			color.CyanString(g.ID),
			output.Truncate(g.Name, 25),
			output.Dim(aliases),
			output.Dim(fmt.Sprintf("%d", len(g.Techniques))),
		)
	}
	t.Flush()

	if *page < totalPages {
		color.New(color.Faint).Printf("\n  --page %d/%d\n\n", *page, totalPages)
	}
}

func mitreSoftware(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("mitre software", flag.ContinueOnError)
	search := fs.String("search", "", "Filter by name")
	limit := fs.Int("limit", 30, "Results per page")
	page := fs.Int("page", 1, "Page number")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt
	offset := (*page - 1) * *limit

	m := api.NewMitreAPI(managerClient)
	software, total, err := m.Software(*search, *limit, offset)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(software)
		return
	}

	totalPages := (total + *limit - 1) / *limit
	if totalPages == 0 {
		totalPages = 1
	}
	output.ShowCount(len(software), total, fmt.Sprintf("software - page %d/%d", *page, totalPages))

	t := output.NewTable("ID", "NAME", "TYPE", "PLATFORMS")
	for _, s := range software {
		t.Row(
			color.CyanString(s.ID),
			output.Truncate(s.Name, 30),
			output.Dim(s.Type),
			output.Dim(output.Truncate(strings.Join(s.Platforms, ", "), 30)),
		)
	}
	t.Flush()

	if *page < totalPages {
		color.New(color.Faint).Printf("\n  --page %d/%d\n\n", *page, totalPages)
	}
}

func mitreShow(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: mitre show <technique-id>  e.g. mitre show T1059"))
		return
	}

	m := api.NewMitreAPI(managerClient)
	tech, err := m.Technique(args[0])
	if err != nil {
		printErr(err)
		return
	}

	id := tech.ExternalID
	if id == "" {
		id = tech.ID
	}
	printSection(fmt.Sprintf("%s - %s", id, tech.Name))
	fmt.Println()

	if len(tech.Platforms) > 0 {
		output.Field("Platforms", strings.Join(tech.Platforms, ", "))
	}
	if len(tech.Tactics) > 0 {
		output.Field("Tactics", strings.Join(tech.Tactics, ", "))
	}

	if tech.Description != "" {
		fmt.Println()
		printSection("Description")
		fmt.Println(wordWrap(tech.Description, 80))
	}

	if len(tech.SubTechniques) > 0 {
		fmt.Println()
		printSection("Sub-techniques")
		for _, s := range tech.SubTechniques {
			fmt.Printf("  %s\n", color.CyanString(s))
		}
	}

	if len(tech.Mitigations) > 0 {
		fmt.Println()
		printSection("Mitigations")
		for _, mit := range tech.Mitigations {
			fmt.Printf("  %s\n", color.GreenString(mit))
		}
	}
	fmt.Println()
}

func wordWrap(text string, width int) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var sb strings.Builder
	lineLen := 0
	for i, w := range words {
		if i > 0 && lineLen+1+len(w) > width {
			sb.WriteByte('\n')
			lineLen = 0
		} else if i > 0 {
			sb.WriteByte(' ')
			lineLen++
		}
		sb.WriteString(w)
		lineLen += len(w)
	}
	return sb.String()
}
