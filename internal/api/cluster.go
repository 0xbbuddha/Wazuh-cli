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

// ClusterNodeHealth is returned by GET /cluster/healthcheck as an array in affected_items.
type ClusterNodeHealth struct {
	Info   ClusterNode       `json:"info"`
	Status ClusterNodeStatus `json:"status"`
}

type ClusterNodeStatus struct {
	SyncIntegrity   string `json:"sync_integrity_free"`
	SyncAgentInfo   string `json:"sync_agent_info_free"`
	SyncAgentGroups string `json:"sync_agent_groups_free"`
}

func (cl *ClusterAPI) Health() ([]ClusterNodeHealth, error) {
	var resp APIResponse[ClusterNodeHealth]
	if err := cl.c.Get("/cluster/healthcheck", &resp); err != nil {
		return nil, err
	}
	return resp.Data.AffectedItems, nil
}
