package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
	"golang.org/x/term"
)

func handleConfig(args []string) {
	if len(args) == 0 || args[0] == "show" {
		configShow()
		return
	}
	switch args[0] {
	case "init":
		configInit()
	default:
		printUnknownSub("config", args[0])
	}
}

func configShow() {
	if cfg == nil || cfg.APIURL == "" {
		printWarn("No configuration found — run: config init")
		return
	}

	rows := []struct{ key, val string }{
		{"api_url", cfg.APIURL},
		{"username", cfg.Auth.Username},
		{"insecure", fmt.Sprintf("%v", cfg.Insecure)},
		{"indexer_url", cfg.Indexer.URL},
		{"indexer_username", cfg.Indexer.Username},
	}

	// Compute column widths
	keyW, valW := len("Setting"), len("Value")
	for _, r := range rows {
		if r.val == "" {
			continue
		}
		if len(r.key) > keyW {
			keyW = len(r.key)
		}
		if len(r.val) > valW {
			valW = len(r.val)
		}
	}

	tableW := 1 + keyW + 2 + valW + 1 // leading space + gap + trailing space

	// Title
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	fmt.Println()
	fmt.Println(lipgloss.PlaceHorizontal(tableW, lipgloss.Center, titleStyle.Render("Configuration")))
	fmt.Println()

	// Table via tabwriter for perfect alignment
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	hdr := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255"))
	fmt.Fprintf(w, " %s\t%s\n", hdr.Render("Setting"), hdr.Render("Value"))
	for _, r := range rows {
		if r.val == "" {
			continue
		}
		fmt.Fprintf(w, " \033[38;5;33m%s\033[0m\t%s\n", r.key, r.val)
	}
	w.Flush()
	fmt.Println()
}

func configInit() {
	home, err := os.UserHomeDir()
	if err != nil {
		printErr(err)
		return
	}
	cfgDir := filepath.Join(home, ".config", "wazuh-cli")
	cfgPath := filepath.Join(cfgDir, "config.toml")

	bold := color.New(color.Bold)
	bold.Println("wazuh-cli config init")
	fmt.Println()
	fmt.Printf("Config path: %s\n", brandDim.Sprint(cfgPath))

	if _, err := os.Stat(cfgPath); err == nil {
		if !promptConfirm(color.YellowString("File already exists. Overwrite?")) {
			fmt.Println("Aborted.")
			return
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
	fmt.Println(brandDim.Sprint("Leave URL empty to skip."))
	fmt.Println()

	indexerURL := promptLine(reader, "Indexer URL", "")
	var indexerUser, indexerPass string
	if indexerURL != "" {
		indexerUser = promptLine(reader, "Indexer username", "admin")
		indexerPass = promptPassword("Indexer password")
	}

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
		printErr(fmt.Errorf("cannot create config directory: %w", err))
		return
	}
	if err := os.WriteFile(cfgPath, []byte(sb.String()), 0600); err != nil {
		printErr(fmt.Errorf("cannot write config: %w", err))
		return
	}

	fmt.Println()
	printOK(fmt.Sprintf("Config written to %s", cfgPath))

	// Reload clients so REPL picks up the new config immediately.
	reloadConfig()
}

func promptLine(r *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", label, brandDim.Sprint(defaultVal))
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
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
