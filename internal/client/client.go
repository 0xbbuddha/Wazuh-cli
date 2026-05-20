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
// On 401, it forces a token refresh and retries once.
func (c *Client) Do(method, path string, body io.Reader) (*http.Response, error) {
	if err := c.ensureToken(); err != nil {
		return nil, err
	}
	// Buffer body so we can retry on 401.
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, err
		}
	}
	doOnce := func() (*http.Response, error) {
		var r io.Reader
		if bodyBytes != nil {
			r = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequest(method, c.baseURL+path, r)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return c.httpClient.Do(req)
	}
	resp, err := doOnce()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		if err := c.ensureToken(); err != nil {
			return nil, fmt.Errorf("session expired - re-authentication failed: %w", err)
		}
		return doOnce()
	}
	return resp, nil
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
	var body io.Reader
	if payload != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(payload); err != nil {
			return err
		}
		body = &buf
	}
	resp, err := c.Do(http.MethodPut, path, body)
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

// PutDecode is like Put but also decodes the response body into dst.
func (c *Client) PutDecode(path string, payload any, dst any) error {
	var body io.Reader
	if payload != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(payload); err != nil {
			return err
		}
		body = &buf
	}
	resp, err := c.Do(http.MethodPut, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	if dst != nil {
		return json.NewDecoder(resp.Body).Decode(dst)
	}
	return nil
}

// Post is a helper for POST requests with a JSON body that decodes the response into dst.
func (c *Client) Post(path string, payload any, dst any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		return err
	}
	resp, err := c.Do(http.MethodPost, path, &buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	if dst != nil {
		return json.NewDecoder(resp.Body).Decode(dst)
	}
	return nil
}

// GetRaw fetches a path and returns the raw response body (no JSON decoding).
func (c *Client) GetRaw(path string) ([]byte, error) {
	resp, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	return b, nil
}

// PutRaw sends a raw body with the given Content-Type (bypasses JSON encoding).
func (c *Client) PutRaw(path, contentType string, body []byte) error {
	if err := c.ensureToken(); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", contentType)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// Delete is a helper for DELETE requests that decodes the response into dst.
func (c *Client) Delete(path string, dst any) error {
	resp, err := c.Do(http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	if dst != nil {
		return json.NewDecoder(resp.Body).Decode(dst)
	}
	return nil
}
