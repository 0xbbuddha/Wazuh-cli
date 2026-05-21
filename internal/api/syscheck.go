package api

import (
	"fmt"
	"net/url"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type SyscheckAPI struct {
	c *client.Client
}

func NewSyscheckAPI(c *client.Client) *SyscheckAPI {
	return &SyscheckAPI{c: c}
}

func (s *SyscheckAPI) Files(agentID, event, search string, limit, offset int) ([]SyscheckFile, int, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	if offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", offset))
	}
	if event != "" {
		params.Set("q", "event="+event)
	}
	if search != "" {
		params.Set("search", search)
	}
	params.Set("sort", "-date")

	var resp APIResponse[SyscheckFile]
	if err := s.c.Get(fmt.Sprintf("/syscheck/%s?%s", agentID, params.Encode()), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (s *SyscheckAPI) LastScan(agentID string) (*SyscheckLastScan, error) {
	var resp APIResponse[SyscheckLastScan]
	if err := s.c.Get(fmt.Sprintf("/syscheck/%s/last_scan", agentID), &resp); err != nil {
		return nil, err
	}
	if len(resp.Data.AffectedItems) == 0 {
		return nil, nil
	}
	return &resp.Data.AffectedItems[0], nil
}

func (s *SyscheckAPI) Scan(agentID string) error {
	var resp APIResponse[string]
	if err := s.c.PutDecode("/syscheck?agents_list="+agentID, nil, &resp); err != nil {
		return err
	}
	if resp.Data.TotalAffectedItems == 0 && len(resp.Data.FailedItems) > 0 {
		return fmt.Errorf("%s", resp.Data.FailedItems[0].Error.Message)
	}
	return nil
}

func (s *SyscheckAPI) Clear(agentID string) error {
	var resp APIResponse[string]
	return s.c.Delete(fmt.Sprintf("/syscheck/%s", agentID), &resp)
}
