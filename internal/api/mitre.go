package api

import (
	"fmt"
	"net/url"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type MitreAPI struct {
	c *client.Client
}

func NewMitreAPI(c *client.Client) *MitreAPI {
	return &MitreAPI{c: c}
}

func (m *MitreAPI) Techniques(search, tactic string, limit, offset int) ([]MITRETechnique, int, error) {
	p := url.Values{}
	p.Set("limit", fmt.Sprintf("%d", limit))
	if offset > 0 {
		p.Set("offset", fmt.Sprintf("%d", offset))
	}
	if search != "" {
		p.Set("search", search)
	}
	if tactic != "" {
		p.Set("phase_name", tactic)
	}
	var resp APIResponse[MITRETechnique]
	if err := m.c.Get("/mitre/techniques?"+p.Encode(), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (m *MitreAPI) Technique(id string) (*MITRETechnique, error) {
	p := url.Values{}
	p.Set("q", "external_id="+id)
	p.Set("limit", "1")
	var resp APIResponse[MITRETechnique]
	if err := m.c.Get("/mitre/techniques?"+p.Encode(), &resp); err != nil {
		return nil, err
	}
	if len(resp.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("technique %q not found", id)
	}
	return &resp.Data.AffectedItems[0], nil
}

func (m *MitreAPI) Tactics(search string, limit, offset int) ([]MITRETactic, int, error) {
	p := url.Values{}
	p.Set("limit", fmt.Sprintf("%d", limit))
	if offset > 0 {
		p.Set("offset", fmt.Sprintf("%d", offset))
	}
	if search != "" {
		p.Set("search", search)
	}
	var resp APIResponse[MITRETactic]
	if err := m.c.Get("/mitre/tactics?"+p.Encode(), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (m *MitreAPI) Groups(search string, limit, offset int) ([]MITREGroup, int, error) {
	p := url.Values{}
	p.Set("limit", fmt.Sprintf("%d", limit))
	if offset > 0 {
		p.Set("offset", fmt.Sprintf("%d", offset))
	}
	if search != "" {
		p.Set("search", search)
	}
	var resp APIResponse[MITREGroup]
	if err := m.c.Get("/mitre/groups?"+p.Encode(), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (m *MitreAPI) Software(search string, limit, offset int) ([]MITRESoftware, int, error) {
	p := url.Values{}
	p.Set("limit", fmt.Sprintf("%d", limit))
	if offset > 0 {
		p.Set("offset", fmt.Sprintf("%d", offset))
	}
	if search != "" {
		p.Set("search", search)
	}
	var resp APIResponse[MITRESoftware]
	if err := m.c.Get("/mitre/software?"+p.Encode(), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}
