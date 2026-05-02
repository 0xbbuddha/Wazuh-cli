package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type ActiveResponseAPI struct {
	c *client.Client
}

func NewActiveResponseAPI(c *client.Client) *ActiveResponseAPI {
	return &ActiveResponseAPI{c: c}
}

// ARAlert carries the IP (srcip) used by firewall/host-based AR commands.
type ARAlert struct {
	Data map[string]string `json:"data,omitempty"`
}

type ARRequest struct {
	Command   string   `json:"command"`
	Arguments []string `json:"arguments,omitempty"`
	Alert     *ARAlert `json:"alert"`
}

type ARFailedItem struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	IDs []string `json:"id"`
}

type ARResult struct {
	TotalAffected int
	TotalFailed   int
	Message       string
	FailedItems   []ARFailedItem
}

// Run executes an active response command on one agent or all agents.
// Pass agentID="" or agentID="all" to target every connected agent.
func (a *ActiveResponseAPI) Run(agentID string, req ARRequest) (*ARResult, error) {
	path := "/active-response"
	if agentID != "" && agentID != "all" {
		path += "?agents_list=" + agentID
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := a.c.Do(http.MethodPut, path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the full body so we can show it on error and still decode on success.
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		// Try to extract message from Wazuh JSON error envelope.
		var errResp struct {
			Message string `json:"message"`
			Detail  string `json:"detail"`
		}
		if json.Unmarshal(raw, &errResp) == nil && errResp.Message != "" {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, errResp.Message)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var result struct {
		Data struct {
			TotalAffectedItems int            `json:"total_affected_items"`
			TotalFailedItems   int            `json:"total_failed_items"`
			FailedItems        []ARFailedItem `json:"failed_items"`
		} `json:"data"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return &ARResult{
		TotalAffected: result.Data.TotalAffectedItems,
		TotalFailed:   result.Data.TotalFailedItems,
		Message:       result.Message,
		FailedItems:   result.Data.FailedItems,
	}, nil
}
