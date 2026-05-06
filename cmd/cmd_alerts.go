package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

func handleAlerts(args []string) {
	if len(args) == 0 {
		handleHelp([]string{"alerts"})
		return
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "list":
		alertsList(rest)
	case "heatmap":
		alertsHeatmap(rest)
	case "search":
		alertsSearch(rest)
	default:
		printUnknownSub("alerts", sub)
	}
}

func alertsList(args []string) {
	if !needsIndexer() {
		return
	}
	fs := flag.NewFlagSet("alerts list", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "Number of alerts to show")
	level := fs.Int("level", 0, "Minimum alert level (0 = all)")
	agentID := fs.String("agent", "", "Filter by agent ID")
	watch := fs.Bool("watch", false, "Refresh alerts continuously")
	interval := fs.Int("interval", 5, "Refresh interval in seconds (used with --watch)")
	outFmt := fs.String("o", "table", "Output format: table or json")
	if err := fs.Parse(args); err != nil {
		return
	}
	output.Format = *outFmt
	if *watch {
		alertsWatch(*limit, *level, *agentID, *interval)
		return
	}
	printAlerts(*limit, *level, *agentID)
}

func alertsHeatmap(args []string) {
	if !needsIndexer() {
		return
	}
	fs := flag.NewFlagSet("alerts heatmap", flag.ContinueOnError)
	agentID := fs.String("agent", "", "Filter by agent ID")
	if err := fs.Parse(args); err != nil {
		return
	}
	matrix, err := indexerClient.AlertsHeatmap(*agentID)
	if err != nil {
		printErr(err)
		return
	}
	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var days [7]time.Time
	for i := range days {
		days[i] = today.AddDate(0, 0, i-6)
	}
	printHeatmap(matrix, days)
}

func alertsSearch(args []string) {
	if !needsIndexer() {
		return
	}
	if len(args) == 0 {
		printErr(fmt.Errorf("usage: alerts search <query> [-limit N]"))
		return
	}
	fs := flag.NewFlagSet("alerts search", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "Number of results to show")
	outFmt := fs.String("o", "table", "Output format: table or json")
	// query is everything before the first flag
	query := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return
	}
	output.Format = *outFmt

	alerts, total, err := indexerClient.Search(query, *limit)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(alerts)
		return
	}
	fmt.Printf("Showing %d of %d results for %q\n\n", len(alerts), total, query)
	t := output.NewTable("TIMESTAMP", "LVL", "AGENT", "RULE", "DESCRIPTION")
	for _, a := range alerts {
		t.Row(output.Dim(a.Timestamp), output.ColorLevel(a.Rule.Level),
			output.Cyan(a.Agent.Name), a.Rule.ID,
			output.ColorDesc(a.Rule.Level, a.Rule.Description))
	}
	t.Flush()
}

func printAlerts(limit, level int, agentID string) {
	alerts, total, err := indexerClient.Alerts(limit, level, agentID)
	if err != nil {
		printErr(err)
		return
	}
	if output.Format == "json" {
		output.JSON(alerts)
		return
	}
	output.ShowCount(len(alerts), total, "alerts")
	t := output.NewTable("TIMESTAMP", "LVL", "AGENT", "RULE", "DESCRIPTION")
	for _, a := range alerts {
		t.Row(output.Dim(a.Timestamp), output.ColorLevel(a.Rule.Level),
			output.Cyan(a.Agent.Name), a.Rule.ID,
			output.ColorDesc(a.Rule.Level, output.Truncate(a.Rule.Description, 60)))
	}
	t.Flush()
}

func alertsWatch(limit, level int, agentID string, interval int) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer func() {
		signal.Stop(sig)
		signal.Reset(os.Interrupt)
	}()

	dim := color.New(color.Faint)
	bold := color.New(color.Bold)
	for {
		clearScreen()
		now := time.Now().Format("15:04:05")
		bold.Printf("alerts list --watch")
		fmt.Printf("   ")
		dim.Printf("updated %s · every %ds · Ctrl+C to stop\n\n", now, interval)
		printAlerts(limit, level, agentID)
		select {
		case <-sig:
			clearScreen()
			return
		case <-time.After(time.Duration(interval) * time.Second):
		}
	}
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func printHeatmap(matrix [7][24]int, days [7]time.Time) {
	var nonZero []int
	total := 0
	for _, row := range matrix {
		for _, v := range row {
			total += v
			if v > 0 {
				nonZero = append(nonZero, v)
			}
		}
	}
	sort.Ints(nonZero)
	p := func(pct float64) int {
		if len(nonZero) == 0 {
			return 0
		}
		return nonZero[int(float64(len(nonZero)-1)*pct)]
	}
	p33, p66, p90 := p(0.33), p(0.66), p(0.90)

	cell := func(count int) string {
		switch {
		case count == 0:
			return color.New(color.Faint).Sprint("·")
		case count <= p33:
			return color.New(color.FgGreen).Sprint("░")
		case count <= p66:
			return color.New(color.FgYellow).Sprint("▒")
		case count <= p90:
			return color.New(color.FgYellow, color.Bold).Sprint("▓")
		default:
			return color.New(color.FgRed, color.Bold).Sprint("█")
		}
	}

	peakDay, peakHour, peakCount := 0, 0, 0
	for d, row := range matrix {
		for h, v := range row {
			if v > peakCount {
				peakCount, peakDay, peakHour = v, d, h
			}
		}
	}

	faint := color.New(color.Faint)
	bold := color.New(color.Bold)
	bold.Printf("Alert Heatmap")
	faint.Printf(" — last 7 days   total: %d alerts\n\n", total)

	const labelW = 12
	headerRunes := make([]rune, labelW+28)
	for i := range headerRunes {
		headerRunes[i] = ' '
	}
	for _, m := range []struct {
		pos  int
		text string
	}{
		{0, "0h"}, {6, "6h"}, {12, "12h"}, {18, "18h"}, {23, "23h"},
	} {
		for i, ch := range []rune(m.text) {
			if labelW+m.pos+i < len(headerRunes) {
				headerRunes[labelW+m.pos+i] = ch
			}
		}
	}
	faint.Println(string(headerRunes))

	for d, day := range days {
		label := fmt.Sprintf("%-12s", day.Format("Mon 01/02 "))
		dayTotal := 0
		var sb strings.Builder
		for h := range matrix[d] {
			dayTotal += matrix[d][h]
			sb.WriteString(cell(matrix[d][h]))
		}
		count := faint.Sprintf("  %4d", dayTotal)
		peak := ""
		if d == peakDay {
			peak = color.New(color.FgRed, color.Faint).Sprint(" ← peak")
		}
		fmt.Printf("%s%s%s%s\n", label, sb.String(), count, peak)
	}

	fmt.Println()
	faint.Printf("  ·")
	faint.Printf(" no alerts   ")
	color.New(color.FgGreen).Printf("░")
	faint.Printf(" low   ")
	color.New(color.FgYellow).Printf("▒")
	faint.Printf(" medium   ")
	color.New(color.FgYellow, color.Bold).Printf("▓")
	faint.Printf(" high   ")
	color.New(color.FgRed, color.Bold).Printf("█")
	faint.Printf(" peak\n")
	if peakCount > 0 {
		faint.Printf("  Peak: %d alerts/h  (%s %02d:00)\n",
			peakCount, days[peakDay].Format("Mon 01/02"), peakHour)
	}
}
