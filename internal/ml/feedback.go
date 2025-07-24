package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// FeedbackLoop implements a continuous learning system through user feedback
type FeedbackLoop struct {
	FeedbackDir     string
	FeedbackFile    string
	FeedbackData    FeedbackData
	LearningEnabled bool
	mutex           sync.RWMutex
}

// FeedbackData stores feedback information for continuous learning
type FeedbackData struct {
	FeedbackEntries []FeedbackEntry `json:"feedback_entries"`
	LastUpdated     time.Time       `json:"last_updated"`
	TotalEntries    int             `json:"total_entries"`
	FalsePositives  int             `json:"false_positives"`
	FalseNegatives  int             `json:"false_negatives"`
	TruePositives   int             `json:"true_positives"`
	TrueNegatives   int             `json:"true_negatives"`
}

// FeedbackEntry represents a single feedback entry
type FeedbackEntry struct {
	PackageName     string    `json:"package_name"`
	Version         string    `json:"version"`
	PredictedLabel  string    `json:"predicted_label"`
	ActualLabel     string    `json:"actual_label"`
	ConfidenceScore float64   `json:"confidence_score"`
	FeedbackSource  string    `json:"feedback_source"`
	Timestamp       time.Time `json:"timestamp"`
	Features        map[string]float64 `json:"features,omitempty"`
}

// NewFeedbackLoop creates a new feedback loop
func NewFeedbackLoop(feedbackDir string) (*FeedbackLoop, error) {
	feedbackFile := filepath.Join(feedbackDir, "feedback_data.json")
	
	// Create feedback directory if it doesn't exist
	if err := os.MkdirAll(feedbackDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create feedback directory: %v", err)
	}
	
	// Initialize feedback loop
	feedbackLoop := &FeedbackLoop{
		FeedbackDir:     feedbackDir,
		FeedbackFile:    feedbackFile,
		LearningEnabled: true,
	}
	
	// Load existing feedback data if available
	if err := feedbackLoop.loadFeedbackData(); err != nil {
		// If file doesn't exist, initialize with empty data
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load feedback data: %v", err)
		}
		
		feedbackLoop.FeedbackData = FeedbackData{
			FeedbackEntries: []FeedbackEntry{},
			LastUpdated:     time.Now(),
			TotalEntries:    0,
		}
		
		// Save initial empty data
		if err := feedbackLoop.saveFeedbackData(); err != nil {
			return nil, fmt.Errorf("failed to save initial feedback data: %v", err)
		}
	}
	
	return feedbackLoop, nil
}

// AddFeedback adds a new feedback entry
func (fl *FeedbackLoop) AddFeedback(pkg *types.Package, predictedLabel, actualLabel string, 
	confidenceScore float64, feedbackSource string, features map[string]float64) error {
	
	fl.mutex.Lock()
	defer fl.mutex.Unlock()
	
	// Create new feedback entry
	entry := FeedbackEntry{
		PackageName:     pkg.Name,
		Version:         pkg.Version,
		PredictedLabel:  predictedLabel,
		ActualLabel:     actualLabel,
		ConfidenceScore: confidenceScore,
		FeedbackSource:  feedbackSource,
		Timestamp:       time.Now(),
		Features:        features,
	}
	
	// Add entry to feedback data
	fl.FeedbackData.FeedbackEntries = append(fl.FeedbackData.FeedbackEntries, entry)
	fl.FeedbackData.TotalEntries++
	fl.FeedbackData.LastUpdated = time.Now()
	
	// Update metrics
	fl.updateMetrics(predictedLabel, actualLabel)
	
	// Save updated feedback data
	if err := fl.saveFeedbackData(); err != nil {
		return fmt.Errorf("failed to save feedback data: %v", err)
	}
	
	// If learning is enabled, update the model
	if fl.LearningEnabled {
		if err := fl.updateModel(); err != nil {
			return fmt.Errorf("failed to update model: %v", err)
		}
	}
	
	return nil
}

// GetFeedbackStats returns statistics about the feedback data
func (fl *FeedbackLoop) GetFeedbackStats() map[string]interface{} {
	fl.mutex.RLock()
	defer fl.mutex.RUnlock()
	
	// Calculate accuracy metrics
	totalClassified := fl.FeedbackData.TruePositives + fl.FeedbackData.TrueNegatives + 
		fl.FeedbackData.FalsePositives + fl.FeedbackData.FalseNegatives
	
	accuracy := 0.0
	precision := 0.0
	recall := 0.0
	f1Score := 0.0
	
	if totalClassified > 0 {
		accuracy = float64(fl.FeedbackData.TruePositives+fl.FeedbackData.TrueNegatives) / 
			float64(totalClassified)
	}
	
	if fl.FeedbackData.TruePositives+fl.FeedbackData.FalsePositives > 0 {
		precision = float64(fl.FeedbackData.TruePositives) / 
			float64(fl.FeedbackData.TruePositives+fl.FeedbackData.FalsePositives)
	}
	
	if fl.FeedbackData.TruePositives+fl.FeedbackData.FalseNegatives > 0 {
		recall = float64(fl.FeedbackData.TruePositives) / 
			float64(fl.FeedbackData.TruePositives+fl.FeedbackData.FalseNegatives)
	}
	
	if precision+recall > 0 {
		f1Score = 2 * (precision * recall) / (precision + recall)
	}
	
	return map[string]interface{}{
		"total_entries":    fl.FeedbackData.TotalEntries,
		"true_positives":   fl.FeedbackData.TruePositives,
		"true_negatives":   fl.FeedbackData.TrueNegatives,
		"false_positives":  fl.FeedbackData.FalsePositives,
		"false_negatives":  fl.FeedbackData.FalseNegatives,
		"accuracy":         accuracy,
		"precision":        precision,
		"recall":           recall,
		"f1_score":         f1Score,
		"last_updated":     fl.FeedbackData.LastUpdated,
	}
}

// EnableLearning enables continuous learning
func (fl *FeedbackLoop) EnableLearning() {
	fl.mutex.Lock()
	defer fl.mutex.Unlock()
	fl.LearningEnabled = true
}

// DisableLearning disables continuous learning
func (fl *FeedbackLoop) DisableLearning() {
	fl.mutex.Lock()
	defer fl.mutex.Unlock()
	fl.LearningEnabled = false
}

// GetRecentFeedback returns the most recent feedback entries
func (fl *FeedbackLoop) GetRecentFeedback(limit int) []FeedbackEntry {
	fl.mutex.RLock()
	defer fl.mutex.RUnlock()
	
	if limit <= 0 || limit > len(fl.FeedbackData.FeedbackEntries) {
		limit = len(fl.FeedbackData.FeedbackEntries)
	}
	
	// Get the most recent entries
	start := len(fl.FeedbackData.FeedbackEntries) - limit
	if start < 0 {
		start = 0
	}
	
	return fl.FeedbackData.FeedbackEntries[start:]
}

// loadFeedbackData loads feedback data from file
func (fl *FeedbackLoop) loadFeedbackData() error {
	fl.mutex.Lock()
	defer fl.mutex.Unlock()
	
	// Read feedback data file
	data, err := os.ReadFile(fl.FeedbackFile)
	if err != nil {
		return err
	}
	
	// Unmarshal JSON data
	if err := json.Unmarshal(data, &fl.FeedbackData); err != nil {
		return fmt.Errorf("failed to unmarshal feedback data: %v", err)
	}
	
	return nil
}

// saveFeedbackData saves feedback data to file
func (fl *FeedbackLoop) saveFeedbackData() error {
	// Marshal feedback data to JSON
	data, err := json.MarshalIndent(fl.FeedbackData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal feedback data: %v", err)
	}
	
	// Write to file
	if err := os.WriteFile(fl.FeedbackFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write feedback data: %v", err)
	}
	
	return nil
}

// updateMetrics updates the feedback metrics
func (fl *FeedbackLoop) updateMetrics(predictedLabel, actualLabel string) {
	// Convert labels to boolean (true = threat, false = safe)
	predictedThreat := isThreatLabel(predictedLabel)
	actualThreat := isThreatLabel(actualLabel)
	
	// Update metrics based on prediction vs. actual
	if predictedThreat && actualThreat {
		// True positive
		fl.FeedbackData.TruePositives++
	} else if !predictedThreat && !actualThreat {
		// True negative
		fl.FeedbackData.TrueNegatives++
	} else if predictedThreat && !actualThreat {
		// False positive
		fl.FeedbackData.FalsePositives++
	} else if !predictedThreat && actualThreat {
		// False negative
		fl.FeedbackData.FalseNegatives++
	}
}

// isThreatLabel determines if a label represents a threat
func isThreatLabel(label string) bool {
	label = strings.ToLower(label)
	return label == "threat" || label == "malicious" || 
		label == "critical" || label == "high" || label == "medium"
}

// updateModel updates the ML model based on feedback
func (fl *FeedbackLoop) updateModel() error {
	// This is a placeholder for actual model updating logic
	// In a real implementation, this would:
	// 1. Extract features from feedback entries
	// 2. Update model weights or parameters
	// 3. Save the updated model
	
	// For now, we'll just log that the model would be updated
	fmt.Printf("[Feedback Loop] Model would be updated with %d new entries\n", 
		fl.FeedbackData.TotalEntries)
	
	// Create a model update file to indicate when the model was last updated
	updateFile := filepath.Join(fl.FeedbackDir, "model_updates.json")
	updateData := map[string]interface{}{
		"last_updated": time.Now(),
		"entries_used": fl.FeedbackData.TotalEntries,
		"accuracy": float64(fl.FeedbackData.TruePositives+fl.FeedbackData.TrueNegatives) / 
			float64(fl.FeedbackData.TotalEntries),
	}
	
	// Marshal update data to JSON
	data, err := json.MarshalIndent(updateData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal model update data: %v", err)
	}
	
	// Write to file
	if err := os.WriteFile(updateFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write model update data: %v", err)
	}
	
	return nil
}

// GetFeedbackForPackage gets all feedback entries for a specific package
func (fl *FeedbackLoop) GetFeedbackForPackage(packageName string) []FeedbackEntry {
	fl.mutex.RLock()
	defer fl.mutex.RUnlock()
	
	var entries []FeedbackEntry
	for _, entry := range fl.FeedbackData.FeedbackEntries {
		if entry.PackageName == packageName {
			entries = append(entries, entry)
		}
	}
	
	return entries
}

// GetFeedbackByDate gets feedback entries within a date range
func (fl *FeedbackLoop) GetFeedbackByDate(startDate, endDate time.Time) []FeedbackEntry {
	fl.mutex.RLock()
	defer fl.mutex.RUnlock()
	
	var entries []FeedbackEntry
	for _, entry := range fl.FeedbackData.FeedbackEntries {
		if (entry.Timestamp.Equal(startDate) || entry.Timestamp.After(startDate)) && 
		   (entry.Timestamp.Equal(endDate) || entry.Timestamp.Before(endDate)) {
			entries = append(entries, entry)
		}
	}
	
	return entries
}

// ExportFeedbackData exports feedback data to a JSON file
func (fl *FeedbackLoop) ExportFeedbackData(exportFile string) error {
	fl.mutex.RLock()
	defer fl.mutex.RUnlock()
	
	// Marshal feedback data to JSON
	data, err := json.MarshalIndent(fl.FeedbackData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal feedback data: %v", err)
	}
	
	// Write to export file
	if err := os.WriteFile(exportFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write export file: %v", err)
	}
	
	return nil
}

// ImportFeedbackData imports feedback data from a JSON file
func (fl *FeedbackLoop) ImportFeedbackData(importFile string) error {
	fl.mutex.Lock()
	defer fl.mutex.Unlock()
	
	// Read import file
	data, err := os.ReadFile(importFile)
	if err != nil {
		return fmt.Errorf("failed to read import file: %v", err)
	}
	
	// Unmarshal JSON data
	var importedData FeedbackData
	if err := json.Unmarshal(data, &importedData); err != nil {
		return fmt.Errorf("failed to unmarshal import data: %v", err)
	}
	
	// Merge imported data with existing data
	fl.FeedbackData.FeedbackEntries = append(fl.FeedbackData.FeedbackEntries, 
		importedData.FeedbackEntries...)
	fl.FeedbackData.TotalEntries += importedData.TotalEntries
	fl.FeedbackData.TruePositives += importedData.TruePositives
	fl.FeedbackData.TrueNegatives += importedData.TrueNegatives
	fl.FeedbackData.FalsePositives += importedData.FalsePositives
	fl.FeedbackData.FalseNegatives += importedData.FalseNegatives
	fl.FeedbackData.LastUpdated = time.Now()
	
	// Save merged data
	if err := fl.saveFeedbackData(); err != nil {
		return fmt.Errorf("failed to save merged feedback data: %v", err)
	}
	
	return nil
}