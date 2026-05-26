package api

import (
	"fmt"
	"net/url"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type RootcheckAPI struct {
	c *client.Client
}

func NewRootcheckAPI(c *client.Client) *RootcheckAPI {
	return &RootcheckAPI{c: c}
}

func (r *RootcheckAPI) Results(agentID, status, search string, limit, offset int) ([]RootcheckResult, int, error) {
	p := url.Values{}
	p.Set("limit", fmt.Sprintf("%d", limit))
	if offset > 0 {
		p.Set("offset", fmt.Sprintf("%d", offset))
	}
	if status != "" {
		p.Set("status", status)
	}
	if search != "" {
		p.Set("search", search)
	}
	p.Set("sort", "-date_last")

	var resp APIResponse[RootcheckResult]
	if err := r.c.Get(fmt.Sprintf("/rootcheck/%s?%s", agentID, p.Encode()), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (r *RootcheckAPI) LastScan(agentID string) (*RootcheckLastScan, error) {
	var resp APIResponse[RootcheckLastScan]
	if err := r.c.Get(fmt.Sprintf("/rootcheck/%s/last_scan", agentID), &resp); err != nil {
		return nil, err
	}
	if len(resp.Data.AffectedItems) == 0 {
		return nil, nil
	}
	return &resp.Data.AffectedItems[0], nil
}

func (r *RootcheckAPI) Scan(agentID string) error {
	var resp APIResponse[string]
	if err := r.c.PutDecode("/rootcheck?agents_list="+agentID, nil, &resp); err != nil {
		return err
	}
	if resp.Data.TotalAffectedItems == 0 && len(resp.Data.FailedItems) > 0 {
		return fmt.Errorf("%s", resp.Data.FailedItems[0].Error.Message)
	}
	return nil
}

func (r *RootcheckAPI) Clear(agentID string) error {
	var resp APIResponse[string]
	return r.c.Delete(fmt.Sprintf("/rootcheck/%s", agentID), &resp)
}
