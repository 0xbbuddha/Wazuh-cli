package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// IndexerClient queries the Wazuh Indexer (OpenSearch) on port 9200.
// Authentication is Basic Auth (separate credentials from the manager API).
type IndexerClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

func NewIndexerClient(baseURL, username, password string, insecure bool) *IndexerClient {
	return &IndexerClient{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
			},
		},
	}
}

type AlertsQuery struct {
	Query  map[string]any   `json:"query"`
	Sort   []map[string]any `json:"sort,omitempty"`
	Size   int              `json:"size"`
	Source []string         `json:"_source,omitempty"`
}

type AlertsResponse struct {
	Hits AlertsHits `json:"hits"`
}

type AlertsHits struct {
	Total  AlertsTotal `json:"total"`
	Items  []AlertHit  `json:"hits"`
}

type AlertsTotal struct {
	Value int `json:"value"`
}

type AlertHit struct {
	Source Alert `json:"_source"`
}

type Alert struct {
	Timestamp string    `json:"timestamp"`
	Rule      AlertRule `json:"rule"`
	Agent     AlertAgent `json:"agent"`
	Manager   AlertManager `json:"manager"`
	FullLog   string    `json:"full_log"`
	Location  string    `json:"location"`
}

type AlertRule struct {
	ID          string   `json:"id"`
	Level       int      `json:"level"`
	Description string   `json:"description"`
	Groups      []string `json:"groups"`
}

type AlertAgent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type AlertManager struct {
	Name string `json:"name"`
}

func (ic *IndexerClient) search(index string, query AlertsQuery) (*AlertsResponse, error) {
	body, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, ic.baseURL+"/"+index+"/_search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(ic.username, ic.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ic.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("indexer request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("indexer HTTP %d: %s", resp.StatusCode, b)
	}

	var result AlertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Alerts returns recent alerts from wazuh-alerts-* indices.
func (ic *IndexerClient) Alerts(limit, minLevel int, agentID string) ([]Alert, int, error) {
	must := []map[string]any{}

	if minLevel > 0 {
		must = append(must, map[string]any{
			"range": map[string]any{
				"rule.level": map[string]any{"gte": minLevel},
			},
		})
	}
	if agentID != "" {
		must = append(must, map[string]any{
			"term": map[string]any{"agent.id": agentID},
		})
	}

	var q map[string]any
	if len(must) > 0 {
		q = map[string]any{"bool": map[string]any{"must": must}}
	} else {
		q = map[string]any{"match_all": map[string]any{}}
	}

	query := AlertsQuery{
		Query: q,
		Sort:  []map[string]any{{"timestamp": map[string]any{"order": "desc"}}},
		Size:  limit,
	}

	result, err := ic.search("wazuh-alerts-*", query)
	if err != nil {
		return nil, 0, err
	}

	alerts := make([]Alert, len(result.Hits.Items))
	for i, h := range result.Hits.Items {
		alerts[i] = h.Source
	}
	return alerts, result.Hits.Total.Value, nil
}

// IndexerClusterHealth holds OpenSearch cluster health data.
type IndexerClusterHealth struct {
	ClusterName            string  `json:"cluster_name"`
	Status                 string  `json:"status"`
	TimedOut               bool    `json:"timed_out"`
	NumberOfNodes          int     `json:"number_of_nodes"`
	NumberOfDataNodes      int     `json:"number_of_data_nodes"`
	ActivePrimaryShards    int     `json:"active_primary_shards"`
	ActiveShards           int     `json:"active_shards"`
	RelocatingShards       int     `json:"relocating_shards"`
	InitializingShards     int     `json:"initializing_shards"`
	UnassignedShards       int     `json:"unassigned_shards"`
	ActiveShardsPercent    float64 `json:"active_shards_percent_as_number"`
}

// ClusterHealth queries the OpenSearch /_cluster/health endpoint.
func (ic *IndexerClient) ClusterHealth() (*IndexerClusterHealth, error) {
	req, err := http.NewRequest(http.MethodGet, ic.baseURL+"/_cluster/health", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(ic.username, ic.password)

	resp, err := ic.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("indexer request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("indexer HTTP %d: %s", resp.StatusCode, b)
	}

	var h IndexerClusterHealth
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return nil, err
	}
	return &h, nil
}

// Search performs a full-text search across alert logs and descriptions.
func (ic *IndexerClient) Search(queryStr string, limit int) ([]Alert, int, error) {
	query := AlertsQuery{
		Query: map[string]any{
			"multi_match": map[string]any{
				"query":  queryStr,
				"fields": []string{"full_log", "rule.description", "agent.name"},
			},
		},
		Sort: []map[string]any{{"timestamp": map[string]any{"order": "desc"}}},
		Size: limit,
	}

	result, err := ic.search("wazuh-alerts-*", query)
	if err != nil {
		return nil, 0, err
	}

	alerts := make([]Alert, len(result.Hits.Items))
	for i, h := range result.Hits.Items {
		alerts[i] = h.Source
	}
	return alerts, result.Hits.Total.Value, nil
}
