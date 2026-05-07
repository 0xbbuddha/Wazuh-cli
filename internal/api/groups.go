package api

import (
	"fmt"
	"net/url"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type GroupsAPI struct {
	c *client.Client
}

func NewGroupsAPI(c *client.Client) *GroupsAPI {
	return &GroupsAPI{c: c}
}

func (g *GroupsAPI) List() ([]Group, error) {
	var resp GroupsAPIResponse
	if err := g.c.Get("/groups?limit=500", &resp); err != nil {
		return nil, err
	}
	return resp.Data.AffectedItems, nil
}

func (g *GroupsAPI) Agents(groupID string, limit int) ([]Agent, int, error) {
	path := fmt.Sprintf("/groups/%s/agents?limit=%d", url.PathEscape(groupID), limit)
	var resp APIResponse[Agent]
	if err := g.c.Get(path, &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (g *GroupsAPI) Create(name string) error {
	body := map[string]string{"group_id": name}
	var resp GroupsAPIResponse
	return g.c.Post("/groups", body, &resp)
}

func (g *GroupsAPI) Delete(name string) error {
	return g.c.Delete("/groups?groups_list="+url.QueryEscape(name), nil)
}

func (g *GroupsAPI) Assign(agentID, groupID string) error {
	path := fmt.Sprintf("/agents/group?agents_list=%s&group_id=%s",
		url.QueryEscape(agentID), url.QueryEscape(groupID))
	return g.c.PutDecode(path, struct{}{}, nil)
}

func (g *GroupsAPI) Unassign(agentID, groupID string) error {
	path := fmt.Sprintf("/agents/group?agents_list=%s&groups_list=%s",
		url.QueryEscape(agentID), url.QueryEscape(groupID))
	return g.c.Delete(path, nil)
}

// GetConfig returns the raw XML content of the group's agent.conf.
func (g *GroupsAPI) GetConfig(groupID string) (string, error) {
	path := fmt.Sprintf("/groups/%s/files/agent.conf?raw=true", url.PathEscape(groupID))
	b, err := g.c.GetRaw(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// PutConfig uploads new XML content as the group's agent.conf.
func (g *GroupsAPI) PutConfig(groupID, xmlContent string) error {
	path := fmt.Sprintf("/groups/%s/configuration", url.PathEscape(groupID))
	return g.c.PutRaw(path, "application/xml", []byte(xmlContent))
}
