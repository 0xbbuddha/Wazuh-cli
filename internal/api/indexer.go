package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// IndexerVulnerability is a vulnerability entry from wazuh-states-vulnerabilities-* (Wazuh 4.8+).
type IndexerVulnerability struct {
	Agent   VulnAgent   `json:"agent"`
	Vuln    VulnDetail  `json:"vulnerability"`
	Package VulnPackage `json:"package"`
}

type VulnAgent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type VulnDetail struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Published   string `json:"published_date"`
	Score       VulnScore `json:"score"`
}

type VulnScore struct {
	Base float64 `json:"base"`
}

type VulnPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

type vulnHitsResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Items []struct {
			Source IndexerVulnerability `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// Vulnerabilities queries wazuh-states-vulnerabilities-* for a given agent (Wazuh 4.8+).
func (ic *IndexerClient) Vulnerabilities(agentID, severity string, limit int) ([]IndexerVulnerability, int, error) {
	must := []map[string]any{
		{"term": map[string]any{"agent.id": agentID}},
	}
	if severity != "" {
		// Indexer stores severity in title case ("Critical", not "critical").
		normalized := strings.ToUpper(severity[:1]) + strings.ToLower(severity[1:])
		must = append(must, map[string]any{
			"term": map[string]any{"vulnerability.severity": normalized},
		})
	}

	body, err := json.Marshal(map[string]any{
		"query": map[string]any{"bool": map[string]any{"must": must}},
		"sort":  []map[string]any{{"vulnerability.score.base": map[string]any{"order": "desc"}}},
		"size":  limit,
	})
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest(http.MethodPost,
		ic.baseURL+"/wazuh-states-vulnerabilities-*/_search", bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(ic.username, ic.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ic.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("indexer request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("indexer HTTP %d: %s", resp.StatusCode, b)
	}

	var result vulnHitsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, err
	}

	vulns := make([]IndexerVulnerability, len(result.Hits.Items))
	for i, h := range result.Hits.Items {
		vulns[i] = h.Source
	}
	return vulns, result.Hits.Total.Value, nil
}

// AlertsHourly returns alert counts per hour for the last `hours` hours, oldest first.
func (ic *IndexerClient) AlertsHourly(agentID string, hours int) ([]int, error) {
	must := []map[string]any{
		{"range": map[string]any{
			"timestamp": map[string]any{"gte": fmt.Sprintf("now-%dh", hours)},
		}},
	}
	if agentID != "" {
		must = append(must, map[string]any{"term": map[string]any{"agent.id": agentID}})
	}

	body, err := json.Marshal(map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"must": must}},
		"aggs": map[string]any{
			"by_hour": map[string]any{
				"date_histogram": map[string]any{
					"field":             "timestamp",
					"calendar_interval": "hour",
					"min_doc_count":     0,
					"extended_bounds": map[string]any{
						"min": fmt.Sprintf("now-%dh", hours),
						"max": "now",
					},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, ic.baseURL+"/wazuh-alerts-*/_search", bytes.NewReader(body))
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

	var result struct {
		Aggregations struct {
			ByHour struct {
				Buckets []struct {
					DocCount int `json:"doc_count"`
				} `json:"buckets"`
			} `json:"by_hour"`
		} `json:"aggregations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	counts := make([]int, len(result.Aggregations.ByHour.Buckets))
	for i, b := range result.Aggregations.ByHour.Buckets {
		counts[i] = b.DocCount
	}
	return counts, nil
}

// VulnsBySeverity returns vulnerability counts grouped by severity across all agents.
func (ic *IndexerClient) VulnsBySeverity() (map[string]int, int, error) {
	body, err := json.Marshal(map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_severity": map[string]any{
				"terms": map[string]any{
					"field": "vulnerability.severity",
					"size":  20,
				},
			},
		},
	})
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest(http.MethodPost,
		ic.baseURL+"/wazuh-states-vulnerabilities-*/_search", bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(ic.username, ic.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ic.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("indexer request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("indexer HTTP %d: %s", resp.StatusCode, b)
	}

	var result struct {
		Hits struct {
			Total struct{ Value int `json:"value"` } `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			BySeverity struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"by_severity"`
		} `json:"aggregations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, err
	}

	counts := map[string]int{}
	for _, b := range result.Aggregations.BySeverity.Buckets {
		counts[strings.ToLower(b.Key)] = b.DocCount
	}
	return counts, result.Hits.Total.Value, nil
}

// AlertsHeatmap returns a [7][24]int matrix of alert counts per hour over the last 7 days.
// Index [0] = oldest day (6 days ago), [6] = today. Inner index = UTC hour (0-23).
func (ic *IndexerClient) AlertsHeatmap(agentID string) ([7][24]int, error) {
	must := []map[string]any{
		{"range": map[string]any{
			"timestamp": map[string]any{"gte": "now-7d/d"},
		}},
	}
	if agentID != "" {
		must = append(must, map[string]any{"term": map[string]any{"agent.id": agentID}})
	}

	body, err := json.Marshal(map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"must": must}},
		"aggs": map[string]any{
			"by_hour": map[string]any{
				"date_histogram": map[string]any{
					"field":             "timestamp",
					"calendar_interval": "hour",
					"min_doc_count":     0,
					"extended_bounds": map[string]any{
						"min": "now-7d/d",
						"max": "now",
					},
				},
			},
		},
	})
	if err != nil {
		return [7][24]int{}, err
	}

	req, err := http.NewRequest(http.MethodPost, ic.baseURL+"/wazuh-alerts-*/_search", bytes.NewReader(body))
	if err != nil {
		return [7][24]int{}, err
	}
	req.SetBasicAuth(ic.username, ic.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ic.httpClient.Do(req)
	if err != nil {
		return [7][24]int{}, fmt.Errorf("indexer request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return [7][24]int{}, fmt.Errorf("indexer HTTP %d: %s", resp.StatusCode, b)
	}

	var result struct {
		Aggregations struct {
			ByHour struct {
				Buckets []struct {
					Key      int64 `json:"key"` // Unix ms
					DocCount int   `json:"doc_count"`
				} `json:"buckets"`
			} `json:"by_hour"`
		} `json:"aggregations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return [7][24]int{}, err
	}

	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	var matrix [7][24]int
	for _, b := range result.Aggregations.ByHour.Buckets {
		t := time.UnixMilli(b.Key).UTC()
		day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		dayOffset := int(today.Sub(day).Hours() / 24)
		if dayOffset < 0 || dayOffset > 6 {
			continue
		}
		matrix[6-dayOffset][t.Hour()] = b.DocCount
	}
	return matrix, nil
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
