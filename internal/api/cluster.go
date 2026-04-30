package api

import (
	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type ClusterAPI struct {
	c *client.Client
}

func NewClusterAPI(c *client.Client) *ClusterAPI {
	return &ClusterAPI{c: c}
}

type clusterStatusResponse struct {
	Data    ClusterStatus `json:"data"`
	Message string        `json:"message"`
	Error   int           `json:"error"`
}

func (cl *ClusterAPI) Status() (*ClusterStatus, error) {
	var resp clusterStatusResponse
	if err := cl.c.Get("/cluster/status", &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (cl *ClusterAPI) Nodes() ([]ClusterNode, error) {
	var resp APIResponse[ClusterNode]
	if err := cl.c.Get("/cluster/nodes", &resp); err != nil {
		return nil, err
	}
	return resp.Data.AffectedItems, nil
}

type ClusterHealth struct {
	Nodes map[string]ClusterNodeHealth `json:"nodes"`
}

type ClusterNodeHealth struct {
	Info ClusterNode `json:"info"`
}

type clusterHealthResponse struct {
	Data    ClusterHealth `json:"data"`
	Message string        `json:"message"`
	Error   int           `json:"error"`
}

func (cl *ClusterAPI) Health() (*ClusterHealth, error) {
	var resp clusterHealthResponse
	if err := cl.c.Get("/cluster/healthcheck", &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}
