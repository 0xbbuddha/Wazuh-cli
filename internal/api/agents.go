package api

import (
	"fmt"
	"net/url"

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
