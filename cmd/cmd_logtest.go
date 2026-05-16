package cmd

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/internal/api"
)

func handleLogtest(args []string) {
	if !needsManager() {
		return
	}
	fs := flag.NewFlagSet("logtest", flag.ContinueOnError)
	logFormat := fs.String("format", "syslog", "Log format (syslog, json, audit, etc.)")
	location := fs.String("location", "stdin", "Log source/location label")
	filePath := fs.String("f", "", "Test all lines in a file")
	verbose := fs.Bool("v", false, "Show Wazuh debug messages")
	if err := fs.Parse(args); err != nil {
		return
	}

	lt := api.NewLogtestAPI(managerClient)
	rest := fs.Args()

	switch {
	case len(rest) > 0:
		token := runLogtest(lt, strings.Join(rest, " "), *logFormat, *location, "", *verbose)
		lt.Close(token)
	case *filePath != "":
		runLogtestFile(lt, *filePath, *logFormat, *location, *verbose)
	default:
		stat, _ := os.Stdin.Stat()
		isTTY := (stat.Mode() & os.ModeCharDevice) != 0
		runLogtestREPL(lt, isTTY, *logFormat, *location, *verbose)
	}
}

func runLogtest(lt *api.LogtestAPI, event, logFormat, location, token string, verbose bool) string {
	result, err := lt.Run(event, logFormat, location, token)
	if err != nil {
		printErr(err)
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
		brandDim.Println("  - no rule matched")
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
		printErr(err)
		return
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
			printErr(fmt.Errorf("line %d: %v", total, err))
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
		printErr(err)
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
		brandBlue.Println("  Wazuh logtest  -  type a log line and press Enter  (Ctrl+C to exit)")
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
		if line == "q" || line == "exit" || line == "quit" {
			break
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
