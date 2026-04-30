package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

var Format = "table"

var (
	header   = color.New(color.FgCyan, color.Bold)
	bold     = color.New(color.Bold)
	green    = color.New(color.FgGreen)
	yellow   = color.New(color.FgYellow)
	red      = color.New(color.FgRed)
	faint    = color.New(color.Faint)
)

func JSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
	}
}

func NewTable(headers ...string) *Table {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	t := &Table{w: w, first: true}
	t.Row(headers...)
	return t
}

type Table struct {
	w     *tabwriter.Writer
	first bool
}

func (t *Table) Row(cols ...string) {
	for i, c := range cols {
		if i > 0 {
			fmt.Fprint(t.w, "\t")
		}
		if t.first {
			fmt.Fprint(t.w, header.Sprint(c))
		} else {
			fmt.Fprint(t.w, c)
		}
	}
	fmt.Fprintln(t.w)
	t.first = false
}

func (t *Table) Flush() {
	t.w.Flush()
}

func Field(key, value string) {
	fmt.Printf("%-20s %s\n", bold.Sprint(key+":"), value)
}

// ColorStatus colors an agent connection status.
func ColorStatus(s string) string {
	switch strings.ToLower(s) {
	case "active":
		return green.Sprint(s)
	case "disconnected":
		return red.Sprint(s)
	case "never_connected":
		return yellow.Sprint(s)
	case "pending":
		return yellow.Sprint(s)
	default:
		return faint.Sprint(s)
	}
}

// ColorLevel colors a rule/alert level (1-15).
func ColorLevel(level int) string {
	s := fmt.Sprintf("%d", level)
	switch {
	case level >= 12:
		return red.Sprint(s)
	case level >= 8:
		return yellow.Sprint(s)
	case level >= 4:
		return color.New(color.FgCyan).Sprint(s)
	default:
		return faint.Sprint(s)
	}
}

// ColorSeverity colors a vulnerability severity string.
func ColorSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return color.New(color.FgRed, color.Bold).Sprint(s)
	case "high":
		return red.Sprint(s)
	case "medium":
		return yellow.Sprint(s)
	case "low":
		return green.Sprint(s)
	default:
		return faint.Sprint(s)
	}
}

// ColorResult colors a SCA check result.
func ColorResult(s string) string {
	switch strings.ToLower(s) {
	case "passed":
		return green.Sprint(s)
	case "failed":
		return red.Sprint(s)
	case "not applicable":
		return faint.Sprint(s)
	default:
		return s
	}
}

// ColorDaemon colors a daemon status.
func ColorDaemon(s string) string {
	switch strings.ToLower(s) {
	case "running":
		return green.Sprint(s)
	case "stopped":
		return red.Sprint(s)
	default:
		return yellow.Sprint(s)
	}
}
