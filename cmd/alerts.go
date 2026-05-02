package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
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

	var heatmapAgent string
	heatmapCmd := &cobra.Command{
		Use:   "heatmap",
		Short: "7-day x 24-hour alert volume heatmap",
		Run: func(cmd *cobra.Command, args []string) {
			matrix, err := indexerClient.AlertsHeatmap(heatmapAgent)
			if err != nil {
				die(err)
			}
			now := time.Now().UTC()
			today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
			var days [7]time.Time
			for i := range days {
				days[i] = today.AddDate(0, 0, i-6)
			}
			printHeatmap(matrix, days)
		},
	}
	heatmapCmd.Flags().StringVar(&heatmapAgent, "agent", "", "Filter by agent ID")
	cmd.AddCommand(heatmapCmd)

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
			output.Truncate(a.Rule.Description, 60))
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

func printHeatmap(matrix [7][24]int, days [7]time.Time) {
	// Collect all non-zero values to compute adaptive thresholds.
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
		idx := int(float64(len(nonZero)-1) * pct)
		return nonZero[idx]
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

	// Find peak hour.
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

	// Header: hour markers at 0h, 6h, 12h, 18h, 23h.
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

	// Data rows.
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

	// Legend.
	fmt.Println()
	faint.Printf("  ")
	faint.Printf("·")
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
