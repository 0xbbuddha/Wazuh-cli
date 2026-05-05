package api

import (
	"fmt"

	"github.com/0xbbuddha/wazuh-cli/internal/client"
)

type LogtestAPI struct {
	c *client.Client
}

func NewLogtestAPI(c *client.Client) *LogtestAPI {
	return &LogtestAPI{c: c}
}

type logtestEnvelope struct {
	Error int           `json:"error"`
	Data  LogtestResult `json:"data"`
}

func (l *LogtestAPI) Run(event, logFormat, location, token string) (*LogtestResult, error) {
	req := LogtestRequest{
		Event:     event,
		LogFormat: logFormat,
		Location:  location,
		Token:     token,
	}
	var env logtestEnvelope
	if err := l.c.PutDecode("/logtest", req, &env); err != nil {
		return nil, err
	}
	if env.Error != 0 {
		return nil, fmt.Errorf("logtest error %d", env.Error)
	}
	return &env.Data, nil
}

func (l *LogtestAPI) Close(token string) {
	_ = l.c.Delete("/logtest/"+token, nil)
}
