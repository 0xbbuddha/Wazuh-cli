package api

import (
	"fmt"
	"net/url"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type ManagerAPI struct {
	c *client.Client
}

func NewManagerAPI(c *client.Client) *ManagerAPI {
	return &ManagerAPI{c: c}
}

func (m *ManagerAPI) Info() (*ManagerInfo, error) {
	var resp APIResponse[ManagerInfo]
	if err := m.c.Get("/manager/info", &resp); err != nil {
		return nil, err
	}
	if len(resp.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("no info returned by manager")
	}
	return &resp.Data.AffectedItems[0], nil
}

func (m *ManagerAPI) Status() (map[string]string, error) {
	// The API returns affected_items[0] as a flat map of daemon → status.
	var resp APIResponse[map[string]string]
	if err := m.c.Get("/manager/status", &resp); err != nil {
		return nil, err
	}
	if len(resp.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("no status returned by manager")
	}
	return resp.Data.AffectedItems[0], nil
}

func (m *ManagerAPI) Logs(lines int) ([]ManagerLog, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", lines))
	params.Set("sort", "-timestamp")

	var resp APIResponse[ManagerLog]
	if err := m.c.Get("/manager/logs?"+params.Encode(), &resp); err != nil {
		return nil, err
	}
	return resp.Data.AffectedItems, nil
}
