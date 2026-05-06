package output

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"
)

var Format = "table"

var (
	bold   = color.New(color.Bold)
	green  = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
	red    = color.New(color.FgRed)
	faint  = color.New(color.Faint)

	ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

func wazuhBlueStr(s string) string {
	return "\033[38;5;33m\033[1m" + s + "\033[0m"
}

// visibleLen returns the printable width of a string, ignoring ANSI escape codes.
func visibleLen(s string) int {
	return utf8.RuneCountInString(ansiRe.ReplaceAllString(s, ""))
}

// truncate cuts s to maxLen visible characters, appending "..." if needed.
func truncate(s string, maxLen int) string {
	if visibleLen(s) <= maxLen {
		return s
	}
	// strip ANSI before truncating to avoid cutting inside an escape sequence
	plain := ansiRe.ReplaceAllString(s, "")
	runes := []rune(plain)
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}

func JSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
	}
}

// Table buffers all rows, calculates column widths based on visible characters,
// then flushes with correct padding — ANSI codes do not affect alignment.
type Table struct {
	headers []string
	rows    [][]string
	maxCols []int // max visible width per column
}

func NewTable(headers ...string) *Table {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = visibleLen(h)
	}
	return &Table{headers: headers, maxCols: widths}
}

func (t *Table) Row(cols ...string) {
	// Grow maxCols if necessary.
	for len(t.maxCols) < len(cols) {
		t.maxCols = append(t.maxCols, 0)
	}
	row := make([]string, len(cols))
	for i, c := range cols {
		row[i] = c
		if w := visibleLen(c); w > t.maxCols[i] {
			t.maxCols[i] = w
		}
	}
	t.rows = append(t.rows, row)
}

const colPad = 2 // spaces between columns

func (t *Table) Flush() {
	printRow := func(cols []string, isHeader bool) {
		for i, c := range cols {
			if isHeader {
				c = wazuhBlueStr(c)
			}
			vl := visibleLen(c)
			width := t.maxCols[i]
			padding := width - vl
			if i < len(cols)-1 {
				padding += colPad
			}
			fmt.Print(c + strings.Repeat(" ", padding))
		}
		fmt.Println()
	}

	printRow(t.headers, true)
	for _, row := range t.rows {
		printRow(row, false)
	}
}

func Field(key, value string) {
	padded := fmt.Sprintf("%-19s:", key)
	fmt.Printf("%s %s\n", wazuhBlueStr(padded), value)
}

// ShowCount prints "Showing N of M <label>" with colored numbers.
func ShowCount(shown, total int, label string) {
	fmt.Printf("Showing %s of %s %s\n\n",
		color.New(color.FgHiWhite, color.Bold).Sprintf("%d", shown),
		color.New(color.FgHiWhite, color.Bold).Sprintf("%d", total),
		label,
	)
}

// Truncate is exported so commands can trim long fields before passing to Row.
func Truncate(s string, max int) string {
	return truncate(s, max)
}

func ColorStatus(s string) string {
	switch strings.ToLower(s) {
	case "active":
		return green.Sprint(s)
	case "disconnected":
		return red.Sprint(s)
	case "never_connected", "pending":
		return yellow.Sprint(s)
	default:
		return faint.Sprint(s)
	}
}

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

// ColorDesc tints a description string based on alert level.
func ColorDesc(level int, desc string) string {
	switch {
	case level >= 12:
		return color.New(color.FgRed).Sprint(desc)
	case level >= 8:
		return color.New(color.FgYellow).Sprint(desc)
	case level >= 5:
		return desc // default terminal color is fine for medium
	default:
		return faint.Sprint(desc)
	}
}

// Dim returns s in faint/dim style (timestamps, secondary info).
func Dim(s string) string { return faint.Sprint(s) }

// Cyan returns s in dim cyan (agent names, identifiers).
func Cyan(s string) string { return color.New(color.FgCyan).Sprint(s) }

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

// ProgressBar renders a colored filled/empty bar for a 0-100 score.
// Example: [████████████░░░░░░░░] 60%
func ProgressBar(score int) string {
	const width = 20
	filled := (score * width) / 100
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	var c *color.Color
	switch {
	case score >= 80:
		c = green
	case score >= 60:
		c = yellow
	default:
		c = red
	}
	return fmt.Sprintf("[%s] %3d%%", c.Sprint(bar), score)
}

// Sparkline maps a slice of integers to unicode block characters (▁▂▃▄▅▆▇█).
func Sparkline(values []int) string {
	bars := []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	if len(values) == 0 {
		return ""
	}
	maxVal := 0
	for _, v := range values {
		if v > maxVal {
			maxVal = v
		}
	}
	var sb strings.Builder
	for _, v := range values {
		idx := 0
		if maxVal > 0 {
			idx = int(float64(v) / float64(maxVal) * float64(len(bars)-1))
		}
		sb.WriteRune(bars[idx])
	}
	return sb.String()
}

// SeverityBadge renders a colored severity badge like [CRITICAL] or [HIGH].
func SeverityBadge(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return color.New(color.FgRed, color.Bold).Sprint("[CRITICAL]")
	case "high":
		return color.New(color.FgRed).Sprint("[HIGH]")
	case "medium":
		return color.New(color.FgYellow).Sprint("[MEDIUM]")
	case "low":
		return color.New(color.FgGreen).Sprint("[LOW]")
	default:
		if s == "" {
			return faint.Sprint("[NONE]")
		}
		return faint.Sprint("[" + strings.ToUpper(s) + "]")
	}
}
