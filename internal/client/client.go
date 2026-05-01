package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Client struct {
	baseURL    string
	username   string
	password   string
	insecure   bool
	token      string
	tokenExp   time.Time
	cacheFile  string
	mu         sync.Mutex
	httpClient *http.Client
}

type tokenCache struct {
	APIURL    string    `json:"api_url"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func New(baseURL, username, password string, insecure bool) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	c := &Client{
		baseURL:   baseURL,
		username:  username,
		password:  password,
		insecure:  insecure,
		cacheFile: defaultCacheFile(),
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
	c.loadCachedToken()
	return c
}

func defaultCacheFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "wazuh-cli", ".token.json")
}

func (c *Client) loadCachedToken() {
	if c.cacheFile == "" {
		return
	}
	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		return
	}
	var cache tokenCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return
	}
	// Invalidate if it belongs to a different API URL or is about to expire.
	if cache.APIURL != c.baseURL || time.Now().After(cache.ExpiresAt) {
		return
	}
	c.token = cache.Token
	c.tokenExp = cache.ExpiresAt
}

func (c *Client) saveCachedToken() {
	if c.cacheFile == "" {
		return
	}
	cache := tokenCache{
		APIURL:    c.baseURL,
		Token:     c.token,
		ExpiresAt: c.tokenExp,
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return
	}
	// Ensure the directory exists.
	_ = os.MkdirAll(filepath.Dir(c.cacheFile), 0700)
	// Write with 0600 so only the owner can read the token.
	_ = os.WriteFile(c.cacheFile, data, 0600)
}

func (c *Client) authenticate() error {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/security/user/authenticate?raw=true", nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: HTTP %d: %s", resp.StatusCode, body)
	}

	token := string(bytes.TrimSpace(body))
	if token == "" {
		return fmt.Errorf("empty token received")
	}

	// Wazuh default token lifetime is 900s; cache with a 30s safety margin.
	c.token = token
	c.tokenExp = time.Now().Add(870 * time.Second)
	c.saveCachedToken()
	return nil
}

func (c *Client) ensureToken() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" || time.Now().After(c.tokenExp) {
		return c.authenticate()
	}
	return nil
}

// Do executes an authenticated request against the Wazuh manager API.
func (c *Client) Do(method, path string, body io.Reader) (*http.Response, error) {
	if err := c.ensureToken(); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.httpClient.Do(req)
}

// Get is a helper for GET requests that decodes JSON into dst.
func (c *Client) Get(path string, dst any) error {
	resp, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// Put is a helper for PUT requests with a JSON body.
func (c *Client) Put(path string, payload any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		return err
	}
	resp, err := c.Do(http.MethodPut, path, &buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}
