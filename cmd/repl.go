package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chzyer/readline"

	"github.com/0xbbuddha/wazuh-cli/config"
	"github.com/0xbbuddha/wazuh-cli/internal/api"
	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

// StartupFlags holds command-line overrides passed at launch.
type StartupFlags struct {
	Server   string
	User     string
	Password string
	Insecure bool
}

func buildPrompt() string {
	// wazuh = bold white, (user@host) = dim gray, > = Wazuh blue
	const name = "\033[38;5;46m\033[1mwazuh\033[0m"
	const arrow = "\033[38;5;33m>\033[0m"
	if cfg == nil || cfg.APIURL == "" {
		return name + " \033[90m(not connected)\033[0m " + arrow + " "
	}
	host := cfg.APIURL
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return fmt.Sprintf("%s \033[90m(%s@%s)\033[0m %s ", name, cfg.Auth.Username, host, arrow)
}

func buildCompleter() *readline.PrefixCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("agent",
			readline.PcItem("list"),
			readline.PcItem("get"),
			readline.PcItem("restart"),
			readline.PcItem("summary"),
			readline.PcItem("enroll"),
			readline.PcItem("add"),
			readline.PcItem("remove"),
			readline.PcItem("upgrade"),
			readline.PcItem("groups"),
		),
		readline.PcItem("alerts",
			readline.PcItem("list"),
			readline.PcItem("heatmap"),
			readline.PcItem("search"),
		),
		readline.PcItem("ar",
			readline.PcItem("list"),
			readline.PcItem("run"),
		),
		readline.PcItem("cluster",
			readline.PcItem("status"),
			readline.PcItem("nodes"),
			readline.PcItem("health"),
			readline.PcItem("indexer"),
		),
		readline.PcItem("config",
			readline.PcItem("show"),
			readline.PcItem("init"),
		),
		readline.PcItem("dashboard"),
		readline.PcItem("groups",
			readline.PcItem("list"),
			readline.PcItem("agents"),
			readline.PcItem("create"),
			readline.PcItem("delete"),
			readline.PcItem("assign"),
			readline.PcItem("unassign"),
			readline.PcItem("config"),
			readline.PcItem("config-edit"),
		),
		readline.PcItem("logtest"),
		readline.PcItem("manager",
			readline.PcItem("info"),
			readline.PcItem("status"),
			readline.PcItem("logs"),
		),
		readline.PcItem("rules",
			readline.PcItem("list"),
			readline.PcItem("get"),
			readline.PcItem("groups"),
		),
		readline.PcItem("sca",
			readline.PcItem("list"),
			readline.PcItem("checks"),
		),
		readline.PcItem("syscollector",
			readline.PcItem("hardware"),
			readline.PcItem("os"),
			readline.PcItem("packages"),
			readline.PcItem("ports"),
			readline.PcItem("processes"),
			readline.PcItem("netaddr"),
		),
		readline.PcItem("vuln",
			readline.PcItem("list"),
			readline.PcItem("summary"),
		),
		readline.PcItem("status"),
		readline.PcItem("help"),
		readline.PcItem("clear"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
}

// RunREPL is the main entry point.
func RunREPL(version string, flags StartupFlags) {
	cliVersion = version
	loadConfig()
	applyStartupFlags(flags)

	fmt.Print("\033[2J\033[3J\033[H") // clear screen + scrollback
	printBanner()

	if cfg != nil && cfg.APIURL != "" {
		printInfo(fmt.Sprintf("Connected to %s as %s", cfg.APIURL, cfg.Auth.Username))
		if managerClient != nil {
			m := api.NewManagerAPI(managerClient)
			if info, err := m.Info(); err == nil {
				printInfo(fmt.Sprintf("Wazuh %s - type 'dashboard' for the TUI", info.Version))
			}
		}
	} else {
		printWarn("No configuration found - run 'config init' to get started")
	}
	fmt.Println()

	// Wire promptConfirm to use readline so it respects raw terminal mode.
	replInstance = nil // reset in case of restart

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          buildPrompt(),
		HistoryFile:     os.ExpandEnv("$HOME/.wazuh_cli_history"),
		AutoComplete:    buildCompleter(),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "\033[31m[!]\033[0m readline:", err)
		os.Exit(1)
	}
	defer rl.Close()
	replInstance = rl

	for {
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				break
			}
			continue
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}

		dispatch(line)
		rl.SetPrompt(buildPrompt())
	}

	fmt.Println()
	brandDim.Println("  Goodbye.")
	fmt.Println()
}

func applyStartupFlags(f StartupFlags) {
	if f.Server == "" {
		return
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.APIURL = f.Server
	if f.User != "" {
		cfg.Auth.Username = f.User
	}
	if f.Password != "" {
		cfg.Auth.Password = f.Password
	}
	if f.Insecure {
		cfg.Insecure = true
	}
	managerClient = client.New(cfg.APIURL, cfg.Auth.Username, cfg.Auth.Password, cfg.Insecure)
}
