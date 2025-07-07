package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// ThreatSource represents a source of threat intelligence
type ThreatSource struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	APIKey      string    `json:"api_key,omitempty"`
	Enabled     bool      `json:"enabled"`
	LastUpdated time.Time `json:"last_updated"`
}

// ExternalThreat represents threat data from external sources
type ExternalThreat struct {
	PackageName string                 `json:"package_name"`
	Registry    string                 `json:"registry"`
	ThreatType  string                 `json:"threat_type"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	ReportedAt  time.Time              `json:"reported_at"`
}

// ThreatUpdater manages threat intelligence updates
type ThreatUpdater struct {
	db      *ThreatDB
	sources []ThreatSource
	client  *http.Client
	logger  *log.Logger
}

// NewThreatUpdater creates a new threat updater instance
func NewThreatUpdater(db *ThreatDB, sources []ThreatSource) *ThreatUpdater {
	return &ThreatUpdater{
		db:      db,
		sources: sources,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: log.New(log.Writer(), "[ThreatUpdater] ", log.LstdFlags),
	}
}

// UpdateThreats fetches and updates threat data from all enabled sources
func (tu *ThreatUpdater) UpdateThreats(ctx context.Context) error {
	tu.logger.Println("Starting threat intelligence update...")

	var totalUpdated int
	var errors []string

	for _, source := range tu.sources {
		if !source.Enabled {
			tu.logger.Printf("Skipping disabled source: %s", source.Name)
			continue
		}

		tu.logger.Printf("Updating from source: %s", source.Name)
		threats, err := tu.fetchThreatsFromSource(ctx, source)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to fetch from %s: %v", source.Name, err)
			errors = append(errors, errorMsg)
			tu.logger.Println(errorMsg)
			continue
		}

		updated, err := tu.processThreats(threats, source.Name)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to process threats from %s: %v", source.Name, err)
			errors = append(errors, errorMsg)
			tu.logger.Println(errorMsg)
			continue
		}

		totalUpdated += updated
		tu.logger.Printf("Successfully updated %d threats from %s", updated, source.Name)
	}

	tu.logger.Printf("Threat update completed. Total threats updated: %d", totalUpdated)

	if len(errors) > 0 {
		return fmt.Errorf("update completed with errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// fetchThreatsFromSource fetches threat data from a specific source
func (tu *ThreatUpdater) fetchThreatsFromSource(ctx context.Context, source ThreatSource) ([]ExternalThreat, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", source.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add API key if provided
	if source.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+source.APIKey)
	}

	req.Header.Set("User-Agent", "TypoSentinel/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := tu.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Try to parse as array of threats
	var threats []ExternalThreat
	if err := json.Unmarshal(body, &threats); err != nil {
		// Try to parse as single threat
		var singleThreat ExternalThreat
		if err2 := json.Unmarshal(body, &singleThreat); err2 != nil {
			return nil, fmt.Errorf("failed to parse response as threat data: %w", err)
		}
		threats = []ExternalThreat{singleThreat}
	}

	return threats, nil
}

// processThreats processes and stores threat data in the database
func (tu *ThreatUpdater) processThreats(threats []ExternalThreat, sourceName string) (int, error) {
	var updated int

	for _, threat := range threats {
		// Validate threat data
		if err := tu.validateThreat(threat); err != nil {
			tu.logger.Printf("Skipping invalid threat %s: %v", threat.PackageName, err)
			continue
		}

		// Convert external threat to database record
		record := tu.convertToThreatRecord(threat, sourceName)

		// Check if threat already exists
		existing, err := tu.db.GetThreat(threat.PackageName, threat.Registry)
		if err != nil {
			tu.logger.Printf("Error checking existing threat for %s: %v", threat.PackageName, err)
			continue
		}

		if existing != nil {
			// Update existing threat if new data is more recent or has higher confidence
			if tu.shouldUpdateThreat(existing, record) {
				record.ID = existing.ID
				record.CreatedAt = existing.CreatedAt
				record.UpdatedAt = time.Now()

				if err := tu.updateExistingThreat(record); err != nil {
					tu.logger.Printf("Failed to update threat %s: %v", threat.PackageName, err)
					continue
				}
				updated++
			}
		} else {
			// Add new threat
			if err := tu.db.AddThreat(record); err != nil {
				tu.logger.Printf("Failed to add threat %s: %v", threat.PackageName, err)
				continue
			}
			updated++
		}
	}

	return updated, nil
}

// validateThreat validates external threat data
func (tu *ThreatUpdater) validateThreat(threat ExternalThreat) error {
	if threat.PackageName == "" {
		return fmt.Errorf("package name is required")
	}
	if threat.Registry == "" {
		return fmt.Errorf("registry is required")
	}
	if threat.ThreatType == "" {
		return fmt.Errorf("threat type is required")
	}
	if threat.Severity == "" {
		return fmt.Errorf("severity is required")
	}
	if threat.Confidence < 0 || threat.Confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1")
	}
	return nil
}

// convertToThreatRecord converts external threat to database record
func (tu *ThreatUpdater) convertToThreatRecord(threat ExternalThreat, sourceName string) *ThreatRecord {
	metadataJSON := ""
	if threat.Metadata != nil {
		if data, err := json.Marshal(threat.Metadata); err == nil {
			metadataJSON = string(data)
		}
	}

	return &ThreatRecord{
		PackageName: threat.PackageName,
		Registry:    threat.Registry,
		ThreatType:  threat.ThreatType,
		Severity:    threat.Severity,
		Confidence:  threat.Confidence,
		Description: threat.Description,
		Source:      sourceName,
		Metadata:    metadataJSON,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// shouldUpdateThreat determines if an existing threat should be updated
func (tu *ThreatUpdater) shouldUpdateThreat(existing, new *ThreatRecord) bool {
	// Update if new threat has higher confidence
	if new.Confidence > existing.Confidence {
		return true
	}

	// Update if confidence is equal but new data is more recent
	if new.Confidence == existing.Confidence && new.UpdatedAt.After(existing.UpdatedAt) {
		return true
	}

	// Update if severity is higher (assuming critical > high > medium > low)
	severityOrder := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	existingSeverity := severityOrder[existing.Severity]
	newSeverity := severityOrder[new.Severity]

	if newSeverity > existingSeverity {
		return true
	}

	return false
}

// updateExistingThreat updates an existing threat record
func (tu *ThreatUpdater) updateExistingThreat(record *ThreatRecord) error {
	// This would require implementing an update method in ThreatDB
	// For now, we'll delete and re-add
	if err := tu.db.DeleteThreat(record.PackageName, record.Registry); err != nil {
		return fmt.Errorf("failed to delete existing threat: %w", err)
	}

	if err := tu.db.AddThreat(record); err != nil {
		return fmt.Errorf("failed to re-add updated threat: %w", err)
	}

	return nil
}

// GetUpdateStatus returns the status of threat intelligence sources
func (tu *ThreatUpdater) GetUpdateStatus() []ThreatSource {
	return tu.sources
}

// AddSource adds a new threat intelligence source
func (tu *ThreatUpdater) AddSource(source ThreatSource) {
	tu.sources = append(tu.sources, source)
}

// RemoveSource removes a threat intelligence source by name
func (tu *ThreatUpdater) RemoveSource(name string) {
	for i, source := range tu.sources {
		if source.Name == name {
			tu.sources = append(tu.sources[:i], tu.sources[i+1:]...)
			break
		}
	}
}

// EnableSource enables or disables a threat intelligence source
func (tu *ThreatUpdater) EnableSource(name string, enabled bool) error {
	for i, source := range tu.sources {
		if source.Name == name {
			tu.sources[i].Enabled = enabled
			return nil
		}
	}
	return fmt.Errorf("source %s not found", name)
}
