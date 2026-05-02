# wazuh-cli

Command-line interface for the **Wazuh REST API** (v4.x), written in Go.

```
  ██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗    ██████╗██╗     ██╗
  ██║    ██║██╔══██╗╚══███╔╝██║   ██║██║  ██║   ██╔════╝██║     ██║
  ██║ █╗ ██║███████║  ███╔╝ ██║   ██║███████║───██║     ██║     ██║
  ██║███╗██║██╔══██║ ███╔╝  ██║   ██║██╔══██║   ██║     ██║     ██║
  ╚███╔███╔╝██║  ██║███████╗╚██████╔╝██║  ██║   ╚██████╗███████╗██║
   ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝    ╚═════╝╚══════╝╚═╝
```

---

## Features

- JWT authentication with automatic token refresh and disk cache
- Colored output: status badges, severity indicators, alert levels
- Progress bars for SCA scores `[████████████░░░░░░░░] 60%`
- Sparklines for alert trends `▁▂▃▄▅▆▇█`
- Severity badges `[CRITICAL]` `[HIGH]` `[MEDIUM]` `[LOW]`
- Live TUI dashboard (`wazuh-cli dashboard`)
- `--watch` mode for real-time alert monitoring
- `--output json` on every command for scripting
- Covers the **Wazuh Manager API** (port 55000) and **Wazuh Indexer / OpenSearch** (port 9200)

---

## Installation

### Pre-built binaries

Download the binary for your platform from the [Releases](../../releases) page.

### Build from source

```bash
git clone https://github.com/0xbbuddha/wazuh-cli
cd wazuh-cli
make build
# binaries in build/linux-amd64/ and build/darwin-amd64/
```

**Requirements:** Go 1.21+

---

## Configuration

Run the interactive wizard to generate `~/.config/wazuh-cli/config.toml`:

```bash
wazuh-cli config init
```

Or create the file manually:

```toml
api_url  = "https://wazuh-manager:55000"
insecure = true   # set to true if using a self-signed certificate

[auth]
username = "wazuh-wui"
password = "wazuh-wui"

# optional — required for alerts, heatmap, dashboard, vuln (Wazuh 4.8+)
[indexer]
url      = "https://wazuh-indexer:9200"
username = "kibanaserver"
password = "kibanaserver"
```

> Credentials can be found in `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` on the manager.

---

## Usage

```
wazuh-cli [command] [subcommand] [flags]

Global flags:
  -o, --output string   Output format: table or json (default "table")
```

### agent

```bash
wazuh-cli agent list                          # list all agents
wazuh-cli agent list --status active          # filter by status
wazuh-cli agent list --group default          # filter by group
wazuh-cli agent get 001                       # detailed info for agent 001
wazuh-cli agent restart 001                   # restart agent 001
wazuh-cli agent summary                       # connection status counts
wazuh-cli agent groups                        # list agent groups
```

### manager

```bash
wazuh-cli manager info                        # version, type, path
wazuh-cli manager status                      # status of all Wazuh daemons
wazuh-cli manager logs                        # last 20 log entries
wazuh-cli manager logs --lines 50
```

### syscollector

```bash
wazuh-cli syscollector hardware  001
wazuh-cli syscollector os        001
wazuh-cli syscollector packages  001
wazuh-cli syscollector packages  001 --search nginx
wazuh-cli syscollector ports     001
wazuh-cli syscollector processes 001
wazuh-cli syscollector netaddr   001
```

### rules

```bash
wazuh-cli rules list
wazuh-cli rules list --level 10
wazuh-cli rules list --group sshd
```

### sca

SCA scores are displayed with a color-coded progress bar.

```bash
wazuh-cli sca list 001
wazuh-cli sca checks 001 cis_ubuntu22-04
```

```
POLICY           NAME                  PASS  FAIL  SCORE                      LAST SCAN
cis_ubuntu22-04  CIS Ubuntu 22.04 L1   143   21    [████████████░░░░░░░░]  60%  2026-04-30
```

### vuln

> Requires `[indexer]` section in config.toml for Wazuh 4.8+.

```bash
wazuh-cli vuln list 001
wazuh-cli vuln list 001 --severity critical
wazuh-cli vuln list 001 --severity high
wazuh-cli vuln summary 001
```

```
CVE             SEVERITY    SCORE  PACKAGE    VERSION
CVE-2024-3094   [CRITICAL]  9.8    xz-utils   5.4.1
CVE-2023-4911   [HIGH]      7.8    glibc      2.35
```

### cluster

```bash
wazuh-cli cluster status
wazuh-cli cluster nodes
wazuh-cli cluster health
wazuh-cli cluster indexer   # OpenSearch cluster health (port 9200)
```

### alerts

> Requires `[indexer]` section in config.toml.

```bash
wazuh-cli alerts list
wazuh-cli alerts list --limit 100 --level 8
wazuh-cli alerts list --agent 001
wazuh-cli alerts list --watch                 # real-time refresh
wazuh-cli alerts list --watch --interval 10
wazuh-cli alerts search "failed password"
wazuh-cli alerts heatmap                      # 7-day x 24-hour volume grid
wazuh-cli alerts heatmap --agent 001
```

The heatmap shows alert volume per hour over the last 7 days with adaptive color thresholds:

```
Alert Heatmap — last 7 days   total: 4,821 alerts

            0h    6h    12h   18h  23h
Mon 04/28   ·····▒▒▒░░░▓▓██████▓▓▒▒░░·····    842
Tue 04/29   ·········░░░▒▒▓▓▓███▓▒▒░·······    631 <- peak

  · no alerts   ░ low   ▒ medium   ▓ high   █ peak
```

### ar (active response)

> Requires active response to be configured in `/var/ossec/etc/ossec.conf` on the manager.

```bash
wazuh-cli ar list                             # show available actions
wazuh-cli ar run 001 restart                  # restart Wazuh agent
wazuh-cli ar run 001 block-ip 1.2.3.4         # block an IP via iptables
wazuh-cli ar run 001 unblock-ip 1.2.3.4       # remove IP block
wazuh-cli ar run 001 host-deny 1.2.3.4        # add to /etc/hosts.deny
wazuh-cli ar run all block-ip 1.2.3.4         # run on all agents (asks confirmation)
wazuh-cli ar run all block-ip 1.2.3.4 --force # skip confirmation
```

### dashboard

Live TUI dashboard showing agents, alert trend, vulnerabilities and recent alerts.

```bash
wazuh-cli dashboard                           # auto-refresh every 30s
wazuh-cli dashboard --refresh 60
wazuh-cli dashboard --refresh 0              # disable auto-refresh
```

Controls: `r` to refresh manually, `q` to quit.

### config

```bash
wazuh-cli config           # show active configuration
wazuh-cli config init      # interactive setup wizard
```

### JSON output

All commands support `--output json` for piping or scripting:

```bash
wazuh-cli agent list -o json | jq '.[] | select(.status == "disconnected")'
wazuh-cli vuln list 001 --severity critical -o json | jq '.[].cve'
wazuh-cli alerts list -o json | jq '.[].rule.description'
```

---

## Commands reference

| Command | Subcommands |
|---|---|
| `agent` | `list`, `get`, `restart`, `summary`, `groups` |
| `manager` | `info`, `status`, `logs` |
| `syscollector` | `hardware`, `os`, `packages`, `ports`, `processes`, `netaddr` |
| `rules` | `list` |
| `sca` | `list`, `checks` |
| `vuln` | `list`, `summary` |
| `cluster` | `status`, `nodes`, `health`, `indexer` |
| `alerts` | `list`, `search`, `heatmap` |
| `ar` | `list`, `run` |
| `dashboard` | |
| `config` | `init` |

---

## License

MIT
