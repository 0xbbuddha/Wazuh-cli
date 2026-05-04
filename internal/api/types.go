package api

// APIResponse is the common envelope returned by the Wazuh manager REST API.
type APIResponse[T any] struct {
	Data    APIData[T] `json:"data"`
	Message string     `json:"message"`
	Error   int        `json:"error"`
}

type APIData[T any] struct {
	AffectedItems      []T            `json:"affected_items"`
	TotalAffectedItems int            `json:"total_affected_items"`
	TotalFailedItems   int            `json:"total_failed_items"`
	FailedItems        []APIFailedItem `json:"failed_items"`
}

type APIFailedItem struct {
	ID    []string `json:"id"`
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// --- Agent types ---

type Agent struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	IP            string   `json:"ip"`
	Status        string   `json:"status"`
	Version       string   `json:"version"`
	Manager       string   `json:"manager"`
	NodeName      string   `json:"node_name"`
	DateAdd       string   `json:"dateAdd"`
	LastKeepAlive string   `json:"lastKeepAlive"`
	Group         []string `json:"group"`
	Os            AgentOS  `json:"os"`
}

type AgentOS struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
}

type AgentSummary struct {
	Connection AgentStatusCount  `json:"connection"`
	Config     AgentConfigStatus `json:"configuration"`
}

type AgentStatusCount struct {
	Active         int `json:"active"`
	Disconnected   int `json:"disconnected"`
	NeverConnected int `json:"never_connected"`
	Pending        int `json:"pending"`
	Total          int `json:"total"`
}

type AgentConfigStatus struct {
	Synced    int `json:"synced"`
	NotSynced int `json:"not_synced"`
	Total     int `json:"total"`
}

type AddAgentRequest struct {
	Name string `json:"name"`
	IP   string `json:"ip,omitempty"`
}

type AddAgentResult struct {
	Data struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	} `json:"data"`
	Error int `json:"error"`
}

type UpgradeTask struct {
	Agent  string `json:"agent"`
	TaskID int    `json:"task_id"`
}

type TaskStatus struct {
	TaskID         int    `json:"task_id"`
	AgentID        string `json:"agent_id"`
	Node           string `json:"node"`
	Module         string `json:"module"`
	Command        string `json:"command"`
	CreateTime     string `json:"create_time"`
	LastUpdateTime string `json:"last_update_time"`
	Status         string `json:"status"`
	Error          int    `json:"error"`
	ErrorMessage   string `json:"error_message"`
	Data           string `json:"data"`
}

// --- Manager types ---

type ManagerInfo struct {
	Compilation string `json:"compilation_date"`
	Version     string `json:"version"`
	OpenSSL     string `json:"openssl_support"`
	MaxAgents   string `json:"max_agents"`
	Type        string `json:"type"`
	Path        string `json:"path"`
}

type ManagerLog struct {
	Timestamp   string `json:"timestamp"`
	Tag         string `json:"tag"`
	Level       string `json:"level"`
	Description string `json:"description"`
}

// --- Syscollector types ---

type HardwareInfo struct {
	RAM  HardwareRAM  `json:"ram"`
	CPU  HardwareCPU  `json:"cpu"`
	Scan HardwareScan `json:"scan"`
}

type HardwareRAM struct {
	Total int `json:"total"`
	Free  int `json:"free"`
	Usage int `json:"usage"`
}

type HardwareCPU struct {
	Cores int     `json:"cores"`
	Mhz   float64 `json:"mhz"`
	Name  string  `json:"name"`
}

type HardwareScan struct {
	ID   int    `json:"id"`
	Time string `json:"time"`
}

// OSInfo matches the nested structure returned by GET /syscollector/{id}/os.
type OSInfo struct {
	Os            OSDetails `json:"os"`
	Architecture  string    `json:"architecture"`
	Hostname      string    `json:"hostname"`
	Release       string    `json:"release"`
	Sysname       string    `json:"sysname"`
	KernelVersion string    `json:"version"`
}

type OSDetails struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Codename string `json:"codename"`
}

type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Source       string `json:"source"`
	Description  string `json:"description"`
	Vendor       string `json:"vendor"`
	Format       string `json:"format"`
}

type NetworkAddress struct {
	Address   string `json:"address"`
	Netmask   string `json:"netmask"`
	Broadcast string `json:"broadcast"`
	Proto     string `json:"proto"`
	Iface     string `json:"iface"`
}

type Port struct {
	Protocol string    `json:"protocol"`
	Local    PortLocal `json:"local"`
	State    string    `json:"state"`
	PID      int       `json:"pid"`
	Process  string    `json:"process"`
}

type PortLocal struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type Process struct {
	PID    string `json:"pid"` // API returns pid as string
	Name   string `json:"name"`
	State  string `json:"state"`
	Euser  string `json:"euser"`
	Cmd    string `json:"cmd"`
	PPID   int    `json:"ppid"`
	VMSize int    `json:"vm_size"`
	NLWP   int    `json:"nlwp"`
}

// --- Rules types ---

type Rule struct {
	ID          int      `json:"id"`
	Level       int      `json:"level"`
	Description string   `json:"description"`
	Groups      []string `json:"groups"`
	Filename    string   `json:"filename"`
	Relative    string   `json:"relative_dirname"`
	Status      string   `json:"status"`
}

// --- SCA types ---

type SCAPolicy struct {
	PolicyID     string `json:"policy_id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	PassCount    int    `json:"pass"`
	FailCount    int    `json:"fail"`
	InvalidCount int    `json:"invalid"`
	TotalChecks  int    `json:"total_checks"`
	Score        int    `json:"score"`
	StartScan    string `json:"start_scan"`
	EndScan      string `json:"end_scan"`
}

type SCACheck struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Result      string `json:"result"`
	Rationale   string `json:"rationale"`
	Remediation string `json:"remediation"`
}

// --- Vulnerability types ---

type Vulnerability struct {
	CVE          string `json:"cve"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Severity     string `json:"severity"`
	Published    string `json:"published"`
	Title        string `json:"title"`
	Type         string `json:"type"`
}

// --- Cluster types ---

type ClusterStatus struct {
	Enabled string `json:"enabled"`
	Running string `json:"running"`
}

type ClusterNode struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Version string `json:"version"`
	Type    string `json:"type"`
	Status  string `json:"status"`
}
