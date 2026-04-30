package api

import (
	"fmt"
	"net/url"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type SyscollectorAPI struct {
	c *client.Client
}

func NewSyscollectorAPI(c *client.Client) *SyscollectorAPI {
	return &SyscollectorAPI{c: c}
}

type hardwareResponse struct {
	Data    HardwareInfo `json:"data"`
	Message string       `json:"message"`
	Error   int          `json:"error"`
}

func (s *SyscollectorAPI) Hardware(agentID string) (*HardwareInfo, error) {
	var resp hardwareResponse
	if err := s.c.Get(fmt.Sprintf("/syscollector/%s/hardware", agentID), &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

type osResponse struct {
	Data    APIData[OSInfo] `json:"data"`
	Message string          `json:"message"`
	Error   int             `json:"error"`
}

func (s *SyscollectorAPI) OS(agentID string) (*OSInfo, error) {
	var resp osResponse
	if err := s.c.Get(fmt.Sprintf("/syscollector/%s/os", agentID), &resp); err != nil {
		return nil, err
	}
	if len(resp.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("no OS info for agent %s", agentID)
	}
	return &resp.Data.AffectedItems[0], nil
}

func (s *SyscollectorAPI) Packages(agentID, search string, limit int) ([]Package, int, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	if search != "" {
		params.Set("search", search)
	}

	var resp APIResponse[Package]
	if err := s.c.Get(fmt.Sprintf("/syscollector/%s/packages?%s", agentID, params.Encode()), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (s *SyscollectorAPI) Ports(agentID string, limit int) ([]Port, int, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))

	var resp APIResponse[Port]
	if err := s.c.Get(fmt.Sprintf("/syscollector/%s/ports?%s", agentID, params.Encode()), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (s *SyscollectorAPI) Processes(agentID string, limit int) ([]Process, int, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))

	var resp APIResponse[Process]
	if err := s.c.Get(fmt.Sprintf("/syscollector/%s/processes?%s", agentID, params.Encode()), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (s *SyscollectorAPI) NetAddr(agentID string) ([]NetworkAddress, error) {
	var resp APIResponse[NetworkAddress]
	if err := s.c.Get(fmt.Sprintf("/syscollector/%s/netaddr", agentID), &resp); err != nil {
		return nil, err
	}
	return resp.Data.AffectedItems, nil
}
