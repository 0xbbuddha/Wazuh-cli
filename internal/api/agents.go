package api

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type AgentsAPI struct {
	c *client.Client
}

func NewAgentsAPI(c *client.Client) *AgentsAPI {
	return &AgentsAPI{c: c}
}

func (a *AgentsAPI) List(status, group string, limit int) ([]Agent, int, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	if status != "" {
		params.Set("status", status)
	}
	if group != "" {
		params.Set("group_id", group)
	}

	var resp APIResponse[Agent]
	if err := a.c.Get("/agents?"+params.Encode(), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (a *AgentsAPI) Get(id string) (*Agent, error) {
	var resp APIResponse[Agent]
	if err := a.c.Get("/agents?agents_list="+id, &resp); err != nil {
		return nil, err
	}
	if len(resp.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("agent %s not found", id)
	}
	return &resp.Data.AffectedItems[0], nil
}

func (a *AgentsAPI) Restart(id string) error {
	return a.c.Put("/agents/"+id+"/restart", nil)
}

type agentSummaryResponse struct {
	Data    AgentSummary `json:"data"`
	Message string       `json:"message"`
	Error   int          `json:"error"`
}

func (a *AgentsAPI) Summary() (*AgentSummary, error) {
	var resp agentSummaryResponse
	if err := a.c.Get("/agents/summary/status", &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

type GroupsAPIResponse struct {
	Data    GroupsData `json:"data"`
	Message string     `json:"message"`
	Error   int        `json:"error"`
}

type GroupsData struct {
	AffectedItems      []Group `json:"affected_items"`
	TotalAffectedItems int     `json:"total_affected_items"`
}

type Group struct {
	Name   string `json:"name"`
	Count  int    `json:"count"`
	Config string `json:"configSum"`
	Merged string `json:"mergedSum"`
}

func (a *AgentsAPI) Groups() ([]Group, error) {
	var resp GroupsAPIResponse
	if err := a.c.Get("/groups", &resp); err != nil {
		return nil, err
	}
	return resp.Data.AffectedItems, nil
}

func (a *AgentsAPI) Add(name, ip string) (id, key string, err error) {
	body := AddAgentRequest{Name: name, IP: ip}
	if body.IP == "" {
		body.IP = "any"
	}
	var resp AddAgentResult
	if err := a.c.Post("/agents", body, &resp); err != nil {
		return "", "", err
	}
	return resp.Data.ID, resp.Data.Key, nil
}

func (a *AgentsAPI) Remove(id string) error {
	return a.c.Delete("/agents?agents_list="+id, nil)
}

func (a *AgentsAPI) Upgrade(id, version string) ([]UpgradeTask, error) {
	type upgradeBody struct {
		Version string `json:"version,omitempty"`
	}
	path := "/agents/upgrade?agents_list=" + id
	var resp APIResponse[UpgradeTask]
	if err := a.c.PutDecode(path, upgradeBody{Version: version}, &resp); err != nil {
		return nil, err
	}
	if len(resp.Data.AffectedItems) == 0 && len(resp.Data.FailedItems) > 0 {
		fi := resp.Data.FailedItems[0]
		switch fi.Error.Code {
		case 1703:
			return nil, fmt.Errorf("already up to date: %s", fi.Error.Message)
		case 1822:
			return nil, fmt.Errorf("newer than repo: %s", fi.Error.Message)
		}
		return nil, fmt.Errorf("code %d: %s", fi.Error.Code, fi.Error.Message)
	}
	return resp.Data.AffectedItems, nil
}

func (a *AgentsAPI) TasksStatus(agentIDs []string) ([]TaskStatus, error) {
	params := strings.Join(agentIDs, ",")
	var resp APIResponse[TaskStatus]
	if err := a.c.Get("/tasks/status?agents_list="+params+"&module=upgrade_module", &resp); err != nil {
		return nil, err
	}
	return resp.Data.AffectedItems, nil
}
