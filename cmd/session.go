package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"

	"github.com/0xbbuddha/wazuh-cli/config"
	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/client"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

var (
	cfg           *config.Config
	managerClient *client.Client
	indexerClient *api.IndexerClient
	cliVersion    string
)

var (
	brandDim    = color.New(color.Faint)
	brandBright = color.New(color.Bold)
	brandGreen  = color.New(color.FgGreen, color.Bold)
	brandYellow = color.New(color.FgYellow)
	brandRed    = color.New(color.FgRed, color.Bold)
	brandBlue   = color.New(color.FgHiBlue, color.Bold)
)

func wazuhBlue(s string) string {
	if color.NoColor {
		return s
	}
	return "\033[38;5;33m\033[1m" + s + "\033[0m"
}

func printErr(err error) {
	fmt.Fprintln(os.Stderr,
		color.New(color.FgRed, color.Bold).Sprint("[!]")+
			color.RedString(" "+err.Error()))
}

func printInfo(msg string) {
	fmt.Printf("\033[38;5;33m[*]\033[0m %s\n", msg)
}

func printOK(msg string) {
	color.New(color.FgGreen, color.Bold).Printf("[+] ")
	color.New(color.FgGreen).Println(msg)
}

func printWarn(msg string) {
	color.New(color.FgYellow, color.Bold).Printf("[!] ")
	color.New(color.FgYellow).Println(msg)
}

func printSection(title string) {
	fmt.Printf("\n\033[38;5;33m\033[1m%s\033[0m\n", title)
}

// promptConfirm prints a [y/N] prompt and returns true only if the user types "y".
// Returns false immediately if stdin is not a terminal (non-interactive mode).
func promptConfirm(question string) bool {
	fmt.Print(question + " [y/N] ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Println()
		return false
	}
	return strings.ToLower(strings.TrimSpace(scanner.Text())) == "y"
}

func printUnknownSub(cmd, sub string) {
	fmt.Printf("%s Unknown %s subcommand %q - try 'help %s'\n",
		color.New(color.FgYellow, color.Bold).Sprint("[?]"), cmd, sub, cmd)
}

func needsManager() bool {
	if managerClient == nil {
		printErr(fmt.Errorf("not connected - run: config init"))
		return false
	}
	return true
}

func needsIndexer() bool {
	if indexerClient == nil {
		printErr(fmt.Errorf("indexer not configured - add [indexer] section to config.toml"))
		return false
	}
	return true
}

func loadConfig() {
	var err error
	cfg, err = config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, color.RedString("[!]")+" "+err.Error())
		os.Exit(1)
	}
	if cfg.APIURL != "" {
		managerClient = client.New(cfg.APIURL, cfg.Auth.Username, cfg.Auth.Password, cfg.Insecure)
	}
	if cfg.Indexer.URL != "" {
		indexerClient = api.NewIndexerClient(cfg.Indexer.URL, cfg.Indexer.Username, cfg.Indexer.Password, cfg.Insecure)
	}
	output.Format = "table"
}

// reloadConfig re-reads config after `config init`.
func reloadConfig() {
	var err error
	cfg, err = config.Load()
	if err != nil {
		return
	}
	if cfg.APIURL != "" {
		managerClient = client.New(cfg.APIURL, cfg.Auth.Username, cfg.Auth.Password, cfg.Insecure)
	} else {
		managerClient = nil
	}
	if cfg.Indexer.URL != "" {
		indexerClient = api.NewIndexerClient(cfg.Indexer.URL, cfg.Indexer.Username, cfg.Indexer.Password, cfg.Insecure)
	} else {
		indexerClient = nil
	}
}
