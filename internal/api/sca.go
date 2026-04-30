package api

import (
	"fmt"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type SCAAPI struct {
	c *client.Client
}

func NewSCAAPI(c *client.Client) *SCAAPI {
	return &SCAAPI{c: c}
}

func (s *SCAAPI) List(agentID string) ([]SCAPolicy, error) {
	var resp APIResponse[SCAPolicy]
	if err := s.c.Get(fmt.Sprintf("/sca/%s", agentID), &resp); err != nil {
		return nil, err
	}
	return resp.Data.AffectedItems, nil
}

func (s *SCAAPI) Checks(agentID, policyID string) ([]SCACheck, int, error) {
	var resp APIResponse[SCACheck]
	if err := s.c.Get(fmt.Sprintf("/sca/%s/checks/%s", agentID, policyID), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}
