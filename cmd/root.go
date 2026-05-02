package cmd

import (
	"fmt"
	"os"

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

var banner = `
  ██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗    ██████╗██╗     ██╗
  ██║    ██║██╔══██╗╚══███╔╝██║   ██║██║  ██║   ██╔════╝██║     ██║
  ██║ █╗ ██║███████║  ███╔╝ ██║   ██║███████║───██║     ██║     ██║
  ██║███╗██║██╔══██║ ███╔╝  ██║   ██║██╔══██║   ██║     ██║     ██║
  ╚███╔███╔╝██║  ██║███████╗╚██████╔╝██║  ██║   ╚██████╗███████╗██║
   ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝    ╚═════╝╚══════╝╚═╝`

var rootCmd = &cobra.Command{
	Use:   "wazuh-cli",
	Short: "CLI for the Wazuh REST API",
	Long:  "wazuh-cli — manage Wazuh agents, rules, SCA, vulnerabilities and alerts from the terminal.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		output.Format = outputFormat
		// Allow "config init" to run without a valid config file.
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
		fmt.Println()
		cmd.Help()
	},
}

func printBanner() {
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println(banner)
	dim := color.New(color.Faint)
	dim.Printf("  CLI %s — Wazuh REST API\n", cliVersion)
}

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
	)
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
