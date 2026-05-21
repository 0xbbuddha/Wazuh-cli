# wazuh-cli

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=for-the-badge&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/v/release/0xbbuddha/wazuh-cli?style=for-the-badge&color=blue)](https://github.com/0xbbuddha/wazuh-cli/releases)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](./COPYING)

Interactive REPL for the **Wazuh REST API** (v4.x), written in Go.

```
  ██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗    ██████╗██╗     ██╗
  ██║    ██║██╔══██╗╚══███╔╝██║   ██║██║  ██║   ██╔════╝██║     ██║
  ██║ █╗ ██║███████║  ███╔╝ ██║   ██║███████║───██║     ██║     ██║
  ██║███╗██║██╔══██║ ███╔╝  ██║   ██║██╔══██║   ██║     ██║     ██║
  ╚███╔███╔╝██║  ██║███████╗╚██████╔╝██║  ██║   ╚██████╗███████╗██║
   ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝    ╚═════╝╚══════╝╚═╝
```

---

`wazuh-cli` is a terminal shell built on top of the Wazuh Manager and Indexer REST APIs. It gives you a persistent, history-aware prompt with tab completion, colored output, and access to the full Wazuh surface - agents, alerts, rules, SCA, vulnerabilities, syscollector, active response, and more - without needing to juggle curl commands or the web UI.

It talks to two endpoints: the **Wazuh Manager API** (port 55000) for configuration and agent management, and the **Wazuh Indexer** (port 9200) for alerts, vulnerabilities, and the dashboard. The indexer section is optional - most commands work with just the manager.

---

## Installation

**One-line install (Linux / macOS):**

```bash
curl -fsSL https://raw.githubusercontent.com/0xbbuddha/wazuh-cli/master/install.sh | bash
```

Or download the binary for your platform from the [Releases](../../releases) page, or build from source:

```bash
git clone https://github.com/0xbbuddha/wazuh-cli
cd wazuh-cli
make build
```

**Requirements:** Go 1.26+

---

## Configuration

On first launch, run the interactive setup:

```
wazuh-cli
wazuh > config init
```

This creates `~/.config/wazuh-cli/config.toml`. You can also edit it directly:

```toml
api_url  = "https://wazuh-manager:55000"
insecure = true

[auth]
username = "wazuh-wui"
password = "your-password"

[indexer]
url      = "https://wazuh-indexer:9200"
username = "kibanaserver"
password = "your-password"
```

> Credentials are in `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` on the manager.

---

## How it works

The REPL launches with a prompt showing your connection context. Tab completes all commands and subcommands. Command history persists across sessions in `~/.wazuh_cli_history`.

Every command supports `-o json` for raw JSON output, useful for piping into `jq`. Shell passthrough works with `!<command>` - run arbitrary shell commands without leaving the REPL.

Authentication is handled automatically - JWT tokens are fetched on connect and refreshed transparently on expiry.

---

## Commands

| Command | What it does |
|---|---|
| `status` | Quick overview: manager, agents, indexer health |
| `agent` | List, inspect, restart, enroll, remove, upgrade agents |
| `groups` | Manage agent groups, view and edit `agent.conf` |
| `manager` | Manager info, daemon status, logs |
| `alerts` | List alerts, search, heatmap, real-time watch mode |
| `rules` | Browse and inspect Wazuh rules |
| `sca` | SCA policy results and check details |
| `vuln` | Vulnerability inventory per agent |
| `syscollector` | Hardware, OS, packages, ports, processes, network |
| `cluster` | Cluster status, nodes, health |
| `ar` | List and run active response actions |
| `decoder` | Browse and inspect Wazuh decoders |
| `syscheck` | FIM events, last scan info, trigger scan, clear results |
| `logtest` | Test log lines against the rules engine |
| `dashboard` | Live TUI: agents, alerts, vulnerabilities, SCA, FIM |
| `config` | Show or reinitialize configuration |

Type `help` inside the REPL for a full reference, or `help <command>` for details on a specific command.

---

## License

MIT
