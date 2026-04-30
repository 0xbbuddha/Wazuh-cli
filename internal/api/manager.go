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

type managerInfoResponse struct {
	Data    ManagerInfo `json:"data"`
	Message string      `json:"message"`
	Error   int         `json:"error"`
}

func (m *ManagerAPI) Info() (*ManagerInfo, error) {
	var resp managerInfoResponse
	if err := m.c.Get("/manager/info", &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

type managerStatusResponse struct {
	Data    map[string]string `json:"data"`
	Message string            `json:"message"`
	Error   int               `json:"error"`
}

func (m *ManagerAPI) Status() (map[string]string, error) {
	var resp managerStatusResponse
	if err := m.c.Get("/manager/status", &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
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
