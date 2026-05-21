package api

import (
	"fmt"
	"net/url"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type DecoderAPI struct {
	c *client.Client
}

func NewDecoderAPI(c *client.Client) *DecoderAPI {
	return &DecoderAPI{c: c}
}

func (d *DecoderAPI) List(search string, limit, offset int) ([]Decoder, int, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	if offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", offset))
	}
	if search != "" {
		params.Set("search", search)
	}
	params.Set("status", "enabled")

	var resp APIResponse[Decoder]
	if err := d.c.Get("/decoders?"+params.Encode(), &resp); err != nil {
		return nil, 0, err
	}
	return resp.Data.AffectedItems, resp.Data.TotalAffectedItems, nil
}

func (d *DecoderAPI) Get(name string) (*Decoder, error) {
	var resp APIResponse[Decoder]
	if err := d.c.Get("/decoders?decoder_names="+url.QueryEscape(name), &resp); err != nil {
		return nil, err
	}
	if len(resp.Data.AffectedItems) == 0 {
		return nil, fmt.Errorf("decoder %q not found", name)
	}
	return &resp.Data.AffectedItems[0], nil
}
