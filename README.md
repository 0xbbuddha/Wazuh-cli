# wazuh-cli

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

## Features

- Interactive REPL shell with tab completion and persistent history
- JWT authentication with automatic token refresh and disk cache
- Colored output: status badges, severity indicators, alert levels
- Progress bars for SCA scores `[████████████░░░░░░░░] 60%`
- Sparklines for alert trends `▁▂▃▄▅▆▇█`
- Live TUI dashboard (`dashboard`)
- `--watch` mode for real-time alert monitoring
- `-o json` on every command for scripting
- Shell passthrough with `!<command>` (e.g. `!ping 1.2.3.4`)
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

**Requirements:** Go 1.22+

---

## Configuration

Launch the REPL and run the interactive wizard:

```
wazuh-cli
wazuh > config init
```

Or create `~/.config/wazuh-cli/config.toml` manually:

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

```bash
wazuh-cli              # launch the REPL
wazuh-cli --server https://wazuh:55000 --user wazuh-wui --password secret
```

Once inside the REPL:

```
wazuh (wazuh-wui@wazuh.example.com) > help
```

### REPL tips

| Input | Action |
|---|---|
| `Tab` | Autocomplete commands and subcommands |
| `↑ / ↓` | Navigate command history |
| `!<cmd>` | Run a shell command (`!ping 1.2.3.4`, `!cat /etc/hosts`) |
| `-o json` | Append to any command for JSON output |
| `clear` | Clear the terminal |
| `exit` / `quit` / `Ctrl+D` | Leave the REPL |

---

## Commands

### agent

```
agent list                          # list all agents
agent list --status active          # filter by status
agent list --group default          # filter by group
agent get 001                       # detailed info for agent 001
agent restart 001                   # restart agent 001
agent summary                       # connection & config-sync counts
agent add --name web01 --ip 10.0.0.5
agent remove 001                    # remove agent (asks confirmation)
agent upgrade 001
agent groups                        # list agent groups
```

### groups

```
groups list
groups agents default               # agents in a group
groups create my-group
groups delete my-group
groups assign 001 my-group
groups unassign 001 my-group
groups config my-group              # show agent.conf for the group
groups config-edit my-group         # edit agent.conf in $EDITOR and upload on save
```

### manager

```
manager info                        # version, type, path
manager status                      # status of all Wazuh daemons
manager logs                        # last 20 log entries
manager logs --lines 50
```

### alerts

> Requires `[indexer]` section in config.toml.

```
alerts list
alerts list --limit 100 --level 8
alerts list --agent 001
alerts list --watch                 # real-time refresh
alerts list --watch --interval 10
alerts search "failed password"
alerts heatmap                      # 7-day x 24-hour volume grid
alerts heatmap --agent 001
```

The heatmap shows alert volume per hour over the last 7 days with adaptive color thresholds:

```
Alert Heatmap — last 7 days   total: 4,821 alerts

            0h    6h    12h   18h  23h
Mon 04/28   ·····▒▒▒░░░▓▓██████▓▓▒▒░░·····    842
Tue 04/29   ·········░░░▒▒▓▓▓███▓▒▒░·······    631 <- peak

  · no alerts   ░ low   ▒ medium   ▓ high   █ peak
```

### rules

```
rules list
rules list --level 10
rules list --group sshd
rules get 5710
rules groups
```

### sca

SCA scores are displayed with a color-coded progress bar.

```
sca list 001
sca checks 001 cis_ubuntu22-04
```

```
POLICY           NAME                  PASS  FAIL  SCORE                      LAST SCAN
cis_ubuntu22-04  CIS Ubuntu 22.04 L1   143   21    [████████████░░░░░░░░]  60%  2026-04-30
```

### vuln

> Requires `[indexer]` section in config.toml (Wazuh 4.8+).

```
vuln list 001
vuln list 001 --severity critical
vuln list 001 --severity high
vuln summary 001
```

```
CVE             SEVERITY    SCORE  PACKAGE    VERSION
CVE-2024-3094   [CRITICAL]  9.8    xz-utils   5.4.1
CVE-2023-4911   [HIGH]      7.8    glibc      2.35
```

### syscollector

```
syscollector hardware  001
syscollector os        001
syscollector packages  001
syscollector packages  001 --search nginx
syscollector ports     001
syscollector processes 001
syscollector netaddr   001
```

### cluster

```
cluster status
cluster nodes
cluster health
cluster indexer                     # OpenSearch cluster health (port 9200)
```

### ar (active response)

```
ar list                             # show available actions
ar run 001 restart
ar run 001 block-ip 1.2.3.4
ar run all block-ip 1.2.3.4         # run on all agents (asks confirmation)
ar run all block-ip 1.2.3.4 -f     # skip confirmation
```

### logtest

Test log lines against the Wazuh rules engine.

```
logtest                             # interactive mode
logtest "May  6 12:00:01 host sshd[1234]: Failed password for root"
logtest -f /tmp/sample.log          # test all lines in a file
```

### dashboard

Live TUI dashboard showing agents, alert trend, vulnerabilities and recent alerts.

```
dashboard                           # auto-refresh every 30s
dashboard --refresh 60
dashboard --refresh 0              # disable auto-refresh
```

Controls: `r` to refresh manually, `q` to quit.

### config

```
config show                         # display active configuration
config init                         # interactive setup wizard
```

---

## JSON output

Append `-o json` to any command for raw JSON output:

```
alerts list -o json | jq '.[].rule.description'
vuln list 001 --severity critical -o json | jq '.[].cve'
agent list -o json | jq '.[] | select(.status == "disconnected")'
```

---

## Commands reference

| Command | Subcommands |
|---|---|
| `agent` | `list`, `get`, `restart`, `summary`, `add`, `remove`, `upgrade`, `groups` |
| `groups` | `list`, `agents`, `create`, `delete`, `assign`, `unassign`, `config`, `config-edit` |
| `manager` | `info`, `status`, `logs` |
| `alerts` | `list`, `search`, `heatmap` |
| `rules` | `list`, `get`, `groups` |
| `sca` | `list`, `checks` |
| `vuln` | `list`, `summary` |
| `syscollector` | `hardware`, `os`, `packages`, `ports`, `processes`, `netaddr` |
| `cluster` | `status`, `nodes`, `health`, `indexer` |
| `ar` | `list`, `run` |
| `logtest` | _(interactive or inline)_ |
| `dashboard` | |
| `config` | `show`, `init` |

---

## License

MIT
