package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client represents an ML service client
type Client struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewClient creates a new ML service client
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SimilarityRequest represents a request for similarity analysis
type SimilarityRequest struct {
	PackageName string   `json:"package_name"`
	Candidates  []string `json:"candidates"`
}

// SimilarityResponse represents a response from similarity analysis
type SimilarityResponse struct {
	SimilarPackages []SimilarPackage `json:"similar_packages"`
}

// SimilarPackage represents a similar package result
type SimilarPackage struct {
	Name       string  `json:"name"`
	Similarity float64 `json:"similarity"`
	Reason     string  `json:"reason"`
}

// MaliciousRequest represents a request for malicious package detection
type MaliciousRequest struct {
	PackageName string                 `json:"package_name"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MaliciousResponse represents a response from malicious package detection
type MaliciousResponse struct {
	IsMalicious bool    `json:"is_malicious"`
	Confidence  float64 `json:"confidence"`
	Reasons     []string `json:"reasons"`
}

// FindSimilarPackages finds packages similar to the given package name
func (c *Client) FindSimilarPackages(ctx context.Context, packageName string, candidates []string) ([]SimilarPackage, error) {
	req := SimilarityRequest{
		PackageName: packageName,
		Candidates:  candidates,
	}

	var resp SimilarityResponse
	if err := c.makeRequest(ctx, "POST", "/api/v1/similarity", req, &resp); err != nil {
		return nil, fmt.Errorf("similarity request failed: %w", err)
	}

	return resp.SimilarPackages, nil
}

// CheckMaliciousPackage checks if a package is potentially malicious
func (c *Client) CheckMaliciousPackage(ctx context.Context, packageName string, metadata map[string]interface{}) (*MaliciousResponse, error) {
	req := MaliciousRequest{
		PackageName: packageName,
		Metadata:    metadata,
	}

	var resp MaliciousResponse
	if err := c.makeRequest(ctx, "POST", "/api/v1/malicious", req, &resp); err != nil {
		return nil, fmt.Errorf("malicious check request failed: %w", err)
	}

	return &resp, nil
}

// GetModels returns available ML models
func (c *Client) GetModels(ctx context.Context) ([]string, error) {
	var models []string
	if err := c.makeRequest(ctx, "GET", "/api/v1/models", nil, &models); err != nil {
		return nil, fmt.Errorf("get models request failed: %w", err)
	}

	return models, nil
}

// makeRequest makes an HTTP request to the ML service
func (c *Client) makeRequest(ctx context.Context, method, endpoint string, reqBody interface{}, respBody interface{}) error {
	url := c.baseURL + endpoint

	var body []byte
	var err error
	if reqBody != nil {
		body, err = json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// Health checks the health of the ML service
func (c *Client) Health(ctx context.Context) error {
	return c.makeRequest(ctx, "GET", "/health", nil, nil)
}