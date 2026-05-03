package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/0xbbuddha/wazuh-cli/config"
	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/client"
	"github.com/0xbbuddha/wazuh-cli/internal/output"
)

var (
	cfg           *config.Config
	managerClient *client.Client
	indexerClient *api.IndexerClient
	outputFormat  string
	cliVersion    string
)

// ── brand colors (fatih/color — used outside TUI) ────────────────────────────
var (
	brandDim    = color.New(color.Faint)
	brandBright = color.New(color.Bold)
	brandGreen  = color.New(color.FgGreen, color.Bold)
	brandYellow = color.New(color.FgYellow)
	brandRed    = color.New(color.FgRed, color.Bold)
)

// wazuhBlue renders text in Wazuh brand blue (#3595F9 → 256-color 33).
func wazuhBlue(s string) string {
	if color.NoColor {
		return s
	}
	return "\033[38;5;33m\033[1m" + s + "\033[0m"
}

// brandBlue wraps wazuhBlue for Printf-style use.
var brandBlue = color.New(color.FgHiBlue, color.Bold)

var wazuhBanner = `  ██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗    ██████╗██╗     ██╗
  ██║    ██║██╔══██╗╚══███╔╝██║   ██║██║  ██║   ██╔════╝██║     ██║
  ██║ █╗ ██║███████║  ███╔╝ ██║   ██║███████║───██║     ██║     ██║
  ██║███╗██║██╔══██║ ███╔╝  ██║   ██║██╔══██║   ██║     ██║     ██║
  ╚███╔███╔╝██║  ██║███████╗╚██████╔╝██║  ██║   ╚██████╗███████╗██║
   ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝    ╚═════╝╚══════╝╚═╝`

func printBanner() {
	if color.NoColor {
		fmt.Println(wazuhBanner)
	} else {
		fmt.Println("\033[38;5;33m\033[1m" + wazuhBanner + "\033[0m")
	}
	brandDim.Printf("  v%s  —  Wazuh REST API\n", cliVersion)
}

// ── root command ──────────────────────────────────────────────────────────────
var rootCmd = &cobra.Command{
	Use:   "wazuh-cli",
	Short: "CLI for the Wazuh REST API",
	Long:  "wazuh-cli — manage Wazuh agents, rules, SCA, vulnerabilities and alerts from the terminal.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		output.Format = outputFormat
		if cmd.Name() == "init" && cmd.Parent() != nil && cmd.Parent().Name() == "config" {
			return nil
		}
		if managerClient == nil {
			return fmt.Errorf("no configuration found\n\nRun: wazuh-cli config init")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		printBanner()
		printCustomHelp(cmd)
	},
}

// ── custom help ───────────────────────────────────────────────────────────────
func printCustomHelp(cmd *cobra.Command) {
	sep := brandDim.Sprint(strings.Repeat("─", 52))

	if cmd.Short != "" {
		fmt.Printf("\n  %s\n", brandDim.Sprint(cmd.Short))
	}

	// Usage
	fmt.Printf("\n  %s\n", brandBlue.Sprint("USAGE"))
	fmt.Printf("    %s\n", brandBright.Sprint(cmd.UseLine()))
	if cmd.HasAvailableSubCommands() {
		fmt.Printf("    %s\n", brandBright.Sprint(cmd.CommandPath()+" [command]"))
	}

	fmt.Printf("\n  %s\n", sep)

	// Subcommands
	if cmd.HasAvailableSubCommands() {
		fmt.Printf("\n  %s\n", brandBlue.Sprint("COMMANDS"))
		for _, c := range cmd.Commands() {
			if !c.IsAvailableCommand() || c.Hidden {
				continue
			}
			aliases := ""
			if len(c.Aliases) > 0 {
				aliases = brandDim.Sprintf("  (%s)", strings.Join(c.Aliases, ", "))
			}
			fmt.Printf("    %s  %s%s\n",
				brandBlue.Sprintf("%-20s", c.Name()),
				c.Short,
				aliases)
		}
	}

	// Local flags
	if f := strings.TrimRight(cmd.Flags().FlagUsages(), "\n"); strings.TrimSpace(f) != "" {
		fmt.Printf("\n  %s\n", brandBlue.Sprint("FLAGS"))
		for _, line := range strings.Split(f, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("  %s\n", line)
			}
		}
	}

	// Inherited/global flags
	if f := strings.TrimRight(cmd.InheritedFlags().FlagUsages(), "\n"); strings.TrimSpace(f) != "" {
		fmt.Printf("\n  %s\n", brandBlue.Sprint("GLOBAL FLAGS"))
		for _, line := range strings.Split(f, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("  %s\n", line)
			}
		}
	}

	// Examples
	if cmd.Example != "" {
		fmt.Printf("\n  %s\n", brandBlue.Sprint("EXAMPLES"))
		for _, line := range strings.Split(cmd.Example, "\n") {
			fmt.Printf("  %s\n", brandDim.Sprint(line))
		}
	}

	fmt.Printf("\n  %s\n", sep)
	fmt.Printf("\n  %s\n\n",
		brandDim.Sprintf("Run %s --help for more info on a command.",
			brandBlue.Sprint(cmd.CommandPath()+" [command]")))
}

// ── execute ───────────────────────────────────────────────────────────────────
func Execute(version string) {
	cliVersion = version
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")

	rootCmd.AddCommand(
		newAgentCmd(),
		newManagerCmd(),
		newSyscollectorCmd(),
		newRulesCmd(),
		newSCACmd(),
		newVulnCmd(),
		newClusterCmd(),
		newAlertsCmd(),
		newConfigCmd(),
		newDashboardCmd(),
		newARCmd(),
	)

	// Custom help for all commands — shows banner only for root
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd == rootCmd {
			printBanner()
			fmt.Println()
		}
		printCustomHelp(cmd)
	})
}

func initConfig() {
	var err error
	cfg, err = config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, color.RedString("Error:")+" "+err.Error())
		os.Exit(1)
	}
	if cfg.APIURL != "" {
		managerClient = client.New(cfg.APIURL, cfg.Auth.Username, cfg.Auth.Password, cfg.Insecure)
	}
	if cfg.Indexer.URL != "" {
		indexerClient = api.NewIndexerClient(cfg.Indexer.URL, cfg.Indexer.Username, cfg.Indexer.Password, cfg.Insecure)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, color.RedString("Error:")+" "+err.Error())
	os.Exit(1)
}
