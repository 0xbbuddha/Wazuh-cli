package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "config",
		Short:   "Show or initialize configuration",
		Aliases: []string{"c"},
		Run: func(cmd *cobra.Command, args []string) {
			if cfg == nil || cfg.APIURL == "" {
				fmt.Println(color.YellowString("No configuration found."))
				fmt.Println("Run: wazuh-cli config init")
				return
			}
			fmt.Printf("%-20s %s\n", "API URL:", cfg.APIURL)
			fmt.Printf("%-20s %s\n", "Auth User:", cfg.Auth.Username)
			fmt.Printf("%-20s %s\n", "Indexer URL:", cfg.Indexer.URL)
			fmt.Printf("%-20s %s\n", "Indexer User:", cfg.Indexer.Username)
			fmt.Printf("%-20s %v\n", "Insecure TLS:", cfg.Insecure)
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Interactive wizard to create config.toml",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigInit()
		},
	})

	return cmd
}

func runConfigInit() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cfgDir := filepath.Join(home, ".config", "wazuh-cli")
	cfgPath := filepath.Join(cfgDir, "config.toml")

	bold := color.New(color.Bold)
	bold.Println("wazuh-cli config init")
	fmt.Println()
	fmt.Printf("Config path: %s\n", color.New(color.Faint).Sprint(cfgPath))

	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Print(color.YellowString("File already exists. Overwrite? [y/N] "))
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	fmt.Println()
	bold.Println("Manager API (port 55000)")

	reader := bufio.NewReader(os.Stdin)

	apiURL := promptLine(reader, "URL", "https://localhost:55000")
	username := promptLine(reader, "Username", "wazuh-wui")
	password := promptPassword("Password")
	insecureAnswer := promptLine(reader, "Skip TLS verification [y/N]", "N")
	insecure := strings.ToLower(strings.TrimSpace(insecureAnswer)) == "y"

	fmt.Println()
	bold.Println("OpenSearch Indexer (port 9200, optional)")
	fmt.Println(color.New(color.Faint).Sprint("Leave URL empty to skip."))
	fmt.Println()

	indexerURL := promptLine(reader, "Indexer URL", "")
	var indexerUser, indexerPass string
	if indexerURL != "" {
		indexerUser = promptLine(reader, "Indexer username", "admin")
		indexerPass = promptPassword("Indexer password")
	}

	// Build TOML
	var sb strings.Builder
	insecureStr := "false"
	if insecure {
		insecureStr = "true"
	}
	sb.WriteString(fmt.Sprintf("api_url  = %q\n", apiURL))
	sb.WriteString(fmt.Sprintf("insecure = %s\n", insecureStr))
	sb.WriteString("\n[auth]\n")
	sb.WriteString(fmt.Sprintf("username = %q\n", username))
	sb.WriteString(fmt.Sprintf("password = %q\n", password))
	if indexerURL != "" {
		sb.WriteString("\n[indexer]\n")
		sb.WriteString(fmt.Sprintf("url      = %q\n", indexerURL))
		sb.WriteString(fmt.Sprintf("username = %q\n", indexerUser))
		sb.WriteString(fmt.Sprintf("password = %q\n", indexerPass))
	}

	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		return fmt.Errorf("cannot create config directory: %w", err)
	}
	if err := os.WriteFile(cfgPath, []byte(sb.String()), 0600); err != nil {
		return fmt.Errorf("cannot write config: %w", err)
	}

	fmt.Println()
	color.New(color.FgGreen, color.Bold).Printf("Config written to %s\n", cfgPath)
	return nil
}

func promptLine(r *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", label, color.New(color.Faint).Sprint(defaultVal))
	} else {
		fmt.Printf("  %s: ", label)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

func promptPassword(label string) string {
	fmt.Printf("  %s: ", label)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err == nil {
			return string(pw)
		}
	}
	// Fallback: plain read
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
