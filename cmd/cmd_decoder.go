package cmd

import (
	"flag"
	"fmt"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleDecoder(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"decoder"})
		return
	}
	switch args[0] {
	case "list":
		decoderList(args[1:])
	case "show":
		decoderShow(args[1:])
	default:
		printUnknownSub("decoder", args[0])
	}
}

func decoderList(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("decoder list", flag.ContinueOnError)
	search := fs.String("search", "", "Filter by decoder name (substring)")
	limit := fs.Int("limit", 30, "Results per page")
	page := fs.Int("page", 1, "Page number")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt
	offset := (*page - 1) * *limit

	d := api.NewDecoderAPI(managerClient)
	decoders, total, err := d.List(*search, *limit, offset)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(decoders)
		return
	}

	totalPages := (total + *limit - 1) / *limit
	if totalPages == 0 {
		totalPages = 1
	}
	output.ShowCount(len(decoders), total, fmt.Sprintf("decoders - page %d/%d", *page, totalPages))

	t := output.NewTable("NAME", "PARENT", "PROGRAM", "FILE")
	for _, dec := range decoders {
		t.Row(
			output.Truncate(dec.Name, 30),
			output.Dim(output.Truncate(dec.Details.Parent, 20)),
			output.Dim(output.Truncate(dec.Details.ProgramName, 20)),
			output.Dim(output.Truncate(dec.Filename, 35)),
		)
	}
	t.Flush()

	if *page < totalPages {
		color.New(color.Faint).Printf("\n  --page %d/%d  (--limit %d to change page size)\n\n", *page, totalPages, *limit)
	}
}

func decoderShow(args []string) {
	if !needsManager() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: decoder show <name>"))
		return
	}

	d := api.NewDecoderAPI(managerClient)
	dec, err := d.Get(args[0])
	if err != nil {
		printErr(err)
		return
	}

	printSection("Decoder: " + dec.Name)
	output.Field("Name", dec.Name)
	output.Field("Status", dec.Status)
	output.Field("File", dec.Filename)
	output.Field("Directory", dec.Relative)
	output.Field("Position", fmt.Sprintf("%d", dec.Position))
	fmt.Println()
	printSection("Details")
	if dec.Details.Parent != "" {
		output.Field("Parent", dec.Details.Parent)
	}
	if dec.Details.ProgramName != "" {
		output.Field("Program", dec.Details.ProgramName)
	}
	if dec.Details.Prematch != "" {
		output.Field("Prematch", dec.Details.Prematch)
	}
	if dec.Details.Regex != "" {
		output.Field("Regex", dec.Details.Regex)
	}
	if dec.Details.Order != "" {
		output.Field("Order", dec.Details.Order)
	}
}
