package api

import (
	"fmt"
	"net/url"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type RulesAPI struct {
	c *client.Client
}

func NewRulesAPI(c *client.Client) *RulesAPI {
	return &RulesAPI{c: c}
}

func (r *RulesAPI) List(level int, group string, limit int) ([]Rule, int, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	if level > 0 {
		params.Set("level", fmt.Sprintf("%d", level))
	}
	if group != "" {
		params.Set("group", group)
	}

	var resp APIResponse[Rule]
	if err := r.c.Get("/rules?"+params.Encode(), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (r *RulesAPI) Get(id string) (*Rule, error) {
	var resp APIResponse[Rule]
	if err := r.c.Get("/rules?rule_ids="+id, &resp); err != nil {
		return nil, err
	}
	if len(resp.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("rule %s not found", id)
	}
	return &resp.Data.AffectedItems[0], nil
}

type RuleGroupsResponse struct {
	Data    RuleGroupsData `json:"data"`
	Message string         `json:"message"`
	Error   int            `json:"error"`
}

type RuleGroupsData struct {
	AffectedItems      []string `json:"affected_items"`
	TotalAffectedItems int      `json:"total_affected_items"`
}

func (r *RulesAPI) Groups() ([]string, error) {
	var resp RuleGroupsResponse
	if err := r.c.Get("/rules/groups", &resp); err != nil {
		return nil, err
	}
	return resp.Data.AffectedItems, nil
}
