# wazuh-cli

A command-line interface for the **Wazuh REST API** (v4.x), written in Go.

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

- JWT authentication with **automatic token refresh**
- Colored table output (status, severity, alert levels)
- `--output json` flag on every command for scripting
- Covers the **Wazuh Manager API** (port 55000) and the **Wazuh Indexer / OpenSearch** (port 9200) for alerts

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

Or install directly into `$GOPATH/bin`:

```bash
make install
```

**Requirements:** Go 1.21+

---

## Configuration

Create `~/.config/wazuh-cli/config.toml`:

```toml
api_url  = "https://wazuh-manager:55000"
insecure = true   # set to true if using a self-signed certificate

[auth]
username = "wazuh"
password = "wazuh"

# Optional — required only for the `alerts` commands
[indexer]
url      = "https://wazuh-indexer:9200"
username = "admin"
password = "admin"
```

> **Note:** The `[auth]` credentials are Wazuh Manager API users (port 55000), not the Dashboard/Indexer login.  
> To retrieve or reset them on the manager: `curl -k -u wazuh:wazuh -X POST "https://localhost:55000/security/user/authenticate?raw=true"`

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

```
ID    NAME         STATUS        IP            OS                VERSION   GROUP
000   wazuh-mgr    active        127.0.0.1     Ubuntu 22.04      4.14.5    default
001   web-server   active        10.0.0.10     Debian 12         4.14.5    webservers
002   db-server    disconnected  10.0.0.20     CentOS 7          4.13.0    databases
```

### manager

```bash
wazuh-cli manager info       # version, type, ruleset
wazuh-cli manager status     # status of all Wazuh daemons
wazuh-cli manager logs       # last 20 log entries
wazuh-cli manager logs --lines 50
```

### syscollector

```bash
wazuh-cli syscollector hardware  001          # CPU and RAM info
wazuh-cli syscollector os        001          # OS details
wazuh-cli syscollector packages  001          # installed packages
wazuh-cli syscollector packages  001 --search nginx
wazuh-cli syscollector ports     001          # open / listening ports
wazuh-cli syscollector processes 001          # running processes
wazuh-cli syscollector netaddr   001          # network addresses
```

### rules

```bash
wazuh-cli rules list                   # list all rules
wazuh-cli rules list --level 10        # rules with level >= 10
wazuh-cli rules list --group sshd      # rules in group sshd
wazuh-cli rules get 5710               # details for rule 5710
wazuh-cli rules groups                 # list all rule groups
```

### sca

```bash
wazuh-cli sca list 001                        # SCA policies and scores for agent 001
wazuh-cli sca checks 001 cis_ubuntu22-04      # detailed checks for a policy
```

```
POLICY             NAME                    PASS  FAIL  INVALID  SCORE%  LAST SCAN
cis_ubuntu22-04    CIS Ubuntu 22.04 L1     143   21    0        87      2026-04-30
```

### vuln

```bash
wazuh-cli vuln list 001                       # all vulnerabilities for agent 001
wazuh-cli vuln list 001 --severity critical   # critical only
wazuh-cli vuln summary 001                    # counts grouped by severity
```

```
CVE              SEVERITY   PACKAGE       VERSION   TITLE
CVE-2024-3094    critical   xz-utils      5.4.1     Backdoor in liblzma
CVE-2023-4911    high       glibc         2.35      Looney Tunables
```

### cluster

```bash
wazuh-cli cluster status    # enabled / running
wazuh-cli cluster nodes     # list all nodes
wazuh-cli cluster health    # health check
```

### alerts

> Requires `[indexer]` section in config.toml.

```bash
wazuh-cli alerts list                         # last 20 alerts
wazuh-cli alerts list --limit 100 --level 8   # critical alerts (level >= 8)
wazuh-cli alerts list --agent 001             # alerts for a specific agent
wazuh-cli alerts search "failed password"     # full-text search
```

```
TIMESTAMP                    LVL  AGENT       RULE   DESCRIPTION
2026-04-30T10:42:01.123Z     10   web-server  5763   Multiple authentication failures
2026-04-30T10:41:55.456Z     5    db-server   31103  Rootcheck: /tmp writable by group
```

### JSON output

Every command supports `--output json` for piping or scripting:

```bash
wazuh-cli agent list --output json | jq '.[] | select(.status == "disconnected")'
wazuh-cli vuln list 001 --severity critical --output json | jq '.[].cve'
```

---

## Commands reference

| Command | Subcommands |
|---|---|
| `agent` | `list`, `get`, `restart`, `summary`, `groups` |
| `manager` | `info`, `status`, `logs` |
| `syscollector` | `hardware`, `os`, `packages`, `ports`, `processes`, `netaddr` |
| `rules` | `list`, `get`, `groups` |
| `sca` | `list`, `checks` |
| `vuln` | `list`, `summary` |
| `cluster` | `status`, `nodes`, `health` |
| `alerts` | `list`, `search` |
| `config` | _(show active config)_ |

---

## License

MIT
