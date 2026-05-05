package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
)

func newLogtestCmd() *cobra.Command {
	var (
		logFormat string
		location  string
		filePath  string
		verbose   bool
	)

	cmd := &cobra.Command{
		Use:   "logtest [log event]",
		Short: "Test a log against Wazuh rules",
		Long: `Send a log event through the Wazuh rules engine and see which rule fires.

  Modes:
    logtest "Mar 31 10:00:00 host sshd[1]: Failed password for root"
    logtest -f /var/log/auth.log
    echo "log line" | logtest
    logtest          (interactive REPL)`,
		Example: `  wazuh-cli logtest "Mar 31 10:00:00 host sshd[1]: Failed password for root from 1.2.3.4"
  wazuh-cli logtest -f /var/log/auth.log
  wazuh-cli logtest --format syslog --location syslog`,
		Run: func(cmd *cobra.Command, args []string) {
			lt := api.NewLogtestAPI(managerClient)

			switch {
			case len(args) > 0:
				// Single event from argument
				token := runLogtest(lt, strings.Join(args, " "), logFormat, location, "", verbose)
				lt.Close(token)

			case filePath != "":
				// File mode — test each non-empty line
				runLogtestFile(lt, filePath, logFormat, location, verbose)

			default:
				// Stdin pipe or interactive REPL
				stat, _ := os.Stdin.Stat()
				isTTY := (stat.Mode() & os.ModeCharDevice) != 0
				runLogtestREPL(lt, isTTY, logFormat, location, verbose)
			}
		},
	}

	cmd.Flags().StringVar(&logFormat, "format", "syslog", "Log format (syslog, json, audit, etc.)")
	cmd.Flags().StringVar(&location, "location", "stdin", "Log source/location label")
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Test all lines in a file")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show Wazuh debug messages")
	return cmd
}

// runLogtest sends one event and prints the result. Returns the session token.
func runLogtest(lt *api.LogtestAPI, event, logFormat, location, token string, verbose bool) string {
	result, err := lt.Run(event, logFormat, location, token)
	if err != nil {
		brandRed.Fprintf(os.Stderr, "Error: %v\n", err)
		return token
	}

	if verbose && len(result.Messages) > 0 {
		fmt.Println()
		for _, m := range result.Messages {
			brandDim.Println("  " + m)
		}
	}

	printLogtestResult(result)
	return result.Token
}

func printLogtestResult(result *api.LogtestResult) {
	out := result.Output
	if out == nil || out.Rule == nil {
		brandDim.Println("  — no rule matched")
		fmt.Println()
		return
	}

	r := out.Rule
	lvlStyle := logtestLevelStyle(r.Level)

	fmt.Println()
	fmt.Printf("  %s  %s  %s\n",
		lvlStyle.Sprintf("level %-2d", r.Level),
		color.New(color.Bold, color.FgHiBlue).Sprint("rule "+r.ID),
		color.New(color.Bold).Sprint(r.Description),
	)
	if len(r.Groups) > 0 {
		brandDim.Printf("  groups  %s\n", strings.Join(r.Groups, ", "))
	}
	if out.Decoder != nil && out.Decoder.Name != "" {
		brandDim.Printf("  decoder %s", out.Decoder.Name)
		if out.Decoder.Parent != "" && out.Decoder.Parent != out.Decoder.Name {
			brandDim.Printf("  (parent: %s)", out.Decoder.Parent)
		}
		fmt.Println()
	}

	if len(out.Data) > 0 {
		fmt.Println()
		// Sort keys for consistent output
		keys := make([]string, 0, len(out.Data))
		for k := range out.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := out.Data[k]
			if nested, ok := v.(map[string]any); ok {
				for nk, nv := range nested {
					fmt.Printf("    %-22s %v\n", k+"."+nk, nv)
				}
			} else {
				fmt.Printf("    %-22s %v\n", k, v)
			}
		}
	}
	fmt.Println()
}

func runLogtestFile(lt *api.LogtestAPI, path, logFormat, location string, verbose bool) {
	f, err := os.Open(path)
	if err != nil {
		die(err)
	}
	defer f.Close()

	var token string
	matched, total := 0, 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		total++
		result, err := lt.Run(line, logFormat, location, token)
		if err != nil {
			brandRed.Fprintf(os.Stderr, "Error on line %d: %v\n", total, err)
			continue
		}
		token = result.Token

		if result.Output != nil && result.Output.Rule != nil {
			matched++
			brandDim.Printf("[%d] ", total)
			fmt.Printf("%s\n", line)
			printLogtestResult(result)
		} else if verbose {
			brandDim.Printf("[%d] no match: %s\n", total, line)
		}
	}
	if err := scanner.Err(); err != nil {
		die(err)
	}

	lt.Close(token)
	fmt.Printf("─────────────────────────────\n")
	fmt.Printf("Lines tested : %d\n", total)
	brandGreen.Printf("Matched      : %d\n", matched)
	if total-matched > 0 {
		brandDim.Printf("No match     : %d\n", total-matched)
	}
}

func runLogtestREPL(lt *api.LogtestAPI, isTTY bool, logFormat, location string, verbose bool) {
	var token string
	scanner := bufio.NewScanner(os.Stdin)

	if isTTY {
		brandBlue.Println("  Wazuh logtest  —  type a log line and press Enter  (Ctrl+C to exit)")
		brandDim.Println("  format: " + logFormat + "   location: " + location)
		fmt.Println()
	}

	for {
		if isTTY {
			fmt.Print("» ")
		}
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		token = runLogtest(lt, line, logFormat, location, token, verbose)
	}

	if token != "" {
		lt.Close(token)
	}
}

func logtestLevelStyle(level int) *color.Color {
	switch {
	case level >= 13:
		return color.New(color.Bold, color.FgRed)
	case level >= 10:
		return color.New(color.Bold, color.FgHiRed)
	case level >= 7:
		return color.New(color.FgYellow)
	default:
		return color.New(color.FgGreen)
	}
}
