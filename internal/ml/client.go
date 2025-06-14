package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/typosentinel/typosentinel/pkg/types"
)

// Client provides an interface to the ML service
type Client struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
	apiKey     string
}

// ModelInfo contains information about an ML model
type ModelInfo struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Description string    `json:"description"`
	Type        string    `json:"type"`
	TrainedAt   time.Time `json:"trained_at"`
	Accuracy    float64   `json:"accuracy"`
	Precision   float64   `json:"precision"`
	Recall      float64   `json:"recall"`
	F1Score     float64   `json:"f1_score"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SimilarityRequest represents a request to find similar packages
type SimilarityRequest struct {
	PackageName string   `json:"package_name"`
	Registry    string   `json:"registry"`
	TopK        int      `json:"top_k"`
	Threshold   float64  `json:"threshold"`
	Exclude     []string `json:"exclude,omitempty"`
}

// SimilarityResponse represents a response from the similarity service
type SimilarityResponse struct {
	Results []SimilarityResult `json:"results"`
	Model   string             `json:"model"`
	Time    float64            `json:"time_ms"`
}

// SimilarityResult represents a single similarity result
type SimilarityResult struct {
	PackageName string  `json:"package_name"`
	Registry    string  `json:"registry"`
	Score       float64 `json:"score"`
	Distance    float64 `json:"distance"`
	Rank        int     `json:"rank"`
}

// MaliciousRequest represents a request to check if a package is malicious
type MaliciousRequest struct {
	PackageName string                 `json:"package_name"`
	Registry    string                 `json:"registry"`
	Version     string                 `json:"version,omitempty"`
	Features    map[string]interface{} `json:"features,omitempty"`
}

// MaliciousResponse represents a response from the malicious detection service
type MaliciousResponse struct {
	IsMalicious bool                   `json:"is_malicious"`
	Score       float64                `json:"score"`
	Confidence  float64                `json:"confidence"`
	Reasons     []string               `json:"reasons"`
	Features    map[string]interface{} `json:"features"`
	Model       string                 `json:"model"`
	Time        float64                `json:"time_ms"`
}

// BatchAnalysisRequest represents a batch analysis request
type BatchAnalysisRequest struct {
	Packages []PackageToAnalyze `json:"packages"`
	Options  AnalysisOptions    `json:"options"`
}

// PackageToAnalyze represents a package to analyze
type PackageToAnalyze struct {
	Name     string `json:"name"`
	Registry string `json:"registry"`
	Version  string `json:"version,omitempty"`
}

// AnalysisOptions represents options for analysis
type AnalysisOptions struct {
	CheckSimilarity bool    `json:"check_similarity"`
	CheckMalicious  bool    `json:"check_malicious"`
	SimilarityThreshold float64 `json:"similarity_threshold"`
	MaliciousThreshold  float64 `json:"malicious_threshold"`
	TopK           int     `json:"top_k"`
}

// BatchAnalysisResponse represents a batch analysis response
type BatchAnalysisResponse struct {
	Results []PackageAnalysisResult `json:"results"`
	Time    float64                 `json:"time_ms"`
}

// PackageAnalysisResult represents the analysis result for a single package
type PackageAnalysisResult struct {
	Package        PackageToAnalyze      `json:"package"`
	Similarities   []SimilarityResult    `json:"similarities,omitempty"`
	MaliciousCheck *MaliciousResponse    `json:"malicious_check,omitempty"`
	Threats        []types.Threat        `json:"threats,omitempty"`
	Errors         []string              `json:"errors,omitempty"`
}

// NewClient creates a new ML client
func NewClient(baseURL string, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		timeout: 30 * time.Second,
		apiKey:  apiKey,
	}
}

// GetModels retrieves information about available ML models
func (c *Client) GetModels(ctx context.Context) ([]ModelInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/models", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.addAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var models []ModelInfo
	if err := json.NewDecoder(resp.Body).Decode(&models); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return models, nil
}

// FindSimilarPackages finds packages similar to the given package
func (c *Client) FindSimilarPackages(ctx context.Context, packageName, registry string, topK int, threshold float64) (*SimilarityResponse, error) {
	request := SimilarityRequest{
		PackageName: packageName,
		Registry:    registry,
		TopK:        topK,
		Threshold:   threshold,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/similarity", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.addAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response SimilarityResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// CheckMaliciousPackage checks if a package is malicious
func (c *Client) CheckMaliciousPackage(ctx context.Context, packageName, registry, version string) (*MaliciousResponse, error) {
	request := MaliciousRequest{
		PackageName: packageName,
		Registry:    registry,
		Version:     version,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/malicious", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.addAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response MaliciousResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// BatchAnalyzePackages performs batch analysis of multiple packages
func (c *Client) BatchAnalyzePackages(ctx context.Context, packages []PackageToAnalyze, options AnalysisOptions) (*BatchAnalysisResponse, error) {
	request := BatchAnalysisRequest{
		Packages: packages,
		Options:  options,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/batch", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.addAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response BatchAnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// GetModelInfo retrieves information about a specific model
func (c *Client) GetModelInfo(ctx context.Context, modelName string) (*ModelInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/models/%s", c.baseURL, modelName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.addAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var model ModelInfo
	if err := json.NewDecoder(resp.Body).Decode(&model); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &model, nil
}

// ConvertToThreats converts ML analysis results to threats
func (c *Client) ConvertToThreats(analysisResult *PackageAnalysisResult) []types.Threat {
	var threats []types.Threat

	// Add threats from the analysis result
	if len(analysisResult.Threats) > 0 {
		threats = append(threats, analysisResult.Threats...)
	}

	// Convert similarity results to threats
	if len(analysisResult.Similarities) > 0 {
		for _, sim := range analysisResult.Similarities {
			if sim.Score > 0.85 { // High similarity threshold
				threat := types.Threat{
					ID:              generateThreatID(),
					Package:         analysisResult.Package.Name,
					Version:         analysisResult.Package.Version,
					Registry:        analysisResult.Package.Registry,
					Type:            types.ThreatTypeTyposquatting,
					Severity:        calculateSeverityFromScore(sim.Score),
					Confidence:      sim.Score,
					Description:     fmt.Sprintf("Package '%s' is similar to '%s' (similarity score: %.2f)", analysisResult.Package.Name, sim.PackageName, sim.Score),
					SimilarTo:       sim.PackageName,
					Recommendation:  fmt.Sprintf("Verify if you intended to use '%s' instead of '%s'", sim.PackageName, analysisResult.Package.Name),
					DetectedAt:      time.Now(),
					DetectionMethod: "ml_similarity",
					Evidence: []types.Evidence{{
						Type:        "similarity_score",
						Description: fmt.Sprintf("Similarity score: %.2f", sim.Score),
						Value: map[string]interface{}{
							"score":    sim.Score,
							"distance": sim.Distance,
							"rank":     sim.Rank,
						},
						Score: sim.Score,
					}},
				}
				threats = append(threats, threat)
			}
		}
	}

	// Convert malicious check to threat
	if analysisResult.MaliciousCheck != nil && analysisResult.MaliciousCheck.IsMalicious {
		threat := types.Threat{
			ID:              generateThreatID(),
			Package:         analysisResult.Package.Name,
			Version:         analysisResult.Package.Version,
			Registry:        analysisResult.Package.Registry,
			Type:            types.ThreatTypeMalicious,
			Severity:        calculateSeverityFromScore(analysisResult.MaliciousCheck.Score),
			Confidence:      analysisResult.MaliciousCheck.Confidence,
			Description:     fmt.Sprintf("Package '%s' is likely malicious (score: %.2f)", analysisResult.Package.Name, analysisResult.MaliciousCheck.Score),
			Recommendation:  "Remove this package immediately and investigate any potential compromise",
			DetectedAt:      time.Now(),
			DetectionMethod: "ml_malicious_detection",
			Evidence:        buildMaliciousEvidence(analysisResult.MaliciousCheck),
		}
		threats = append(threats, threat)
	}

	return threats
}

// Helper functions

// addAuthHeaders adds authentication headers to a request
func (c *Client) addAuthHeaders(req *http.Request) {
	if c.apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	}
	req.Header.Set("User-Agent", "TypoSentinel/1.0")
}

// generateThreatID generates a unique threat ID
func generateThreatID() string {
	return fmt.Sprintf("threat_%d", time.Now().UnixNano())
}

// calculateSeverityFromScore calculates severity based on a score
func calculateSeverityFromScore(score float64) types.Severity {
	if score >= 0.9 {
		return types.SeverityCritical
	} else if score >= 0.75 {
		return types.SeverityHigh
	} else if score >= 0.5 {
		return types.SeverityMedium
	}
	return types.SeverityLow
}

// buildMaliciousEvidence builds evidence for malicious detection
func buildMaliciousEvidence(maliciousCheck *MaliciousResponse) []types.Evidence {
	evidence := make([]types.Evidence, 0, len(maliciousCheck.Reasons)+1)

	// Add main evidence
	evidence = append(evidence, types.Evidence{
		Type:        "malicious_score",
		Description: fmt.Sprintf("Malicious score: %.2f (confidence: %.2f)", maliciousCheck.Score, maliciousCheck.Confidence),
		Value: map[string]interface{}{
			"score":      maliciousCheck.Score,
			"confidence": maliciousCheck.Confidence,
			"model":      maliciousCheck.Model,
		},
		Score: maliciousCheck.Score,
	})

	// Add reasons as evidence
	for i, reason := range maliciousCheck.Reasons {
		evidence = append(evidence, types.Evidence{
			Type:        "malicious_reason",
			Description: reason,
			Value: map[string]interface{}{
				"reason_id": i + 1,
			},
			Score: maliciousCheck.Score * 0.9, // Slightly lower score for individual reasons
		})
	}

	// Add features as evidence if available
	if len(maliciousCheck.Features) > 0 {
		evidence = append(evidence, types.Evidence{
			Type:        "malicious_features",
			Description: "Suspicious features detected in package",
			Value:       maliciousCheck.Features,
			Score:       maliciousCheck.Score * 0.8, // Lower score for features
		})
	}

	return evidence
}