package threat_intelligence

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ThreatIntelligenceManager manages real-time threat intelligence feeds and updates
type ThreatIntelligenceManager struct {
	config         *config.Config
	feeds          map[string]ThreatFeed
	threatDatabase *ThreatDatabase
	correlator     *ThreatCorrelator
	alerting       *AlertingSystem
	updater        *RealTimeUpdater
	mu             sync.RWMutex
	logger         *logger.Logger
	isRunning      bool
	lastUpdate     time.Time
	updateInterval time.Duration
}

// ThreatFeed represents an external threat intelligence feed
type ThreatFeed interface {
	// GetName returns the feed name
	GetName() string
	
	// GetType returns the feed type
	GetType() string
	
	// Initialize sets up the feed
	Initialize(ctx context.Context, config map[string]interface{}) error
	
	// FetchThreats retrieves latest threats from the feed
	FetchThreats(ctx context.Context, since time.Time) ([]ThreatIntelligence, error)
	
	// GetStatus returns feed status
	GetStatus() FeedStatus
	
	// Close closes the feed connection
	Close() error
}

// ThreatIntelligence represents a threat intelligence entry
type ThreatIntelligence struct {
	ID              string                 `json:"id"`
	Source          string                 `json:"source"`
	Type            string                 `json:"type"` // "typosquatting", "malware", "supply_chain", etc.
	Severity        string                 `json:"severity"`
	PackageName     string                 `json:"package_name"`
	Ecosystem       string                 `json:"ecosystem"`
	Description     string                 `json:"description"`
	Indicators      []ThreatIndicator      `json:"indicators"`
	References      []string               `json:"references"`
	Tags            []string               `json:"tags"`
	ConfidenceLevel float64                `json:"confidence_level"`
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
	ExpiresAt       *time.Time             `json:"expires_at,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
	RawData         interface{}            `json:"raw_data,omitempty"`
}

// ThreatIndicator represents a specific threat indicator
type ThreatIndicator struct {
	Type        string                 `json:"type"` // "package_name", "hash", "url", "pattern"
	Value       string                 `json:"value"`
	Description string                 `json:"description"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// FeedStatus represents the status of a threat feed
type FeedStatus struct {
	Name           string    `json:"name"`
	State          string    `json:"state"` // "active", "inactive", "error", "disabled"
	LastUpdate     time.Time `json:"last_update"`
	LastError      string    `json:"last_error,omitempty"`
	ThreatCount    int       `json:"threat_count"`
	UpdateInterval time.Duration `json:"update_interval"`
	Healthy        bool      `json:"healthy"`
}

// ThreatCorrelationResult represents the result of threat correlation
type ThreatCorrelationResult struct {
	PackageName     string              `json:"package_name"`
	Matches         []ThreatMatch       `json:"matches"`
	OverallSeverity string              `json:"overall_severity"`
	ConfidenceScore float64             `json:"confidence_score"`
	Recommendations []string            `json:"recommendations"`
	LastUpdated     time.Time           `json:"last_updated"`
}

// ThreatMatch represents a match between a package and threat intelligence
type ThreatMatch struct {
	ThreatID        string    `json:"threat_id"`
	Source          string    `json:"source"`
	MatchType       string    `json:"match_type"` // "exact", "pattern", "similarity"
	MatchConfidence float64   `json:"match_confidence"`
	ThreatType      string    `json:"threat_type"`
	Severity        string    `json:"severity"`
	Description     string    `json:"description"`
	FirstSeen       time.Time `json:"first_seen"`
}

// AlertConfig represents alerting configuration
type AlertConfig struct {
	Enabled         bool                     `json:"enabled"`
	SeverityLevels  []string                 `json:"severity_levels"`
	Channels        []config.AlertChannel    `json:"channels"`
	Throttling      config.ThrottlingConfig  `json:"throttling"`
	Filters         []AlertFilter            `json:"filters"`
}



// AlertFilter represents an alert filter
type AlertFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // "equals", "contains", "regex", "gt", "lt"
	Value    interface{} `json:"value"`
	Action   string      `json:"action"` // "include", "exclude"
}

// NewThreatIntelligenceManager creates a new threat intelligence manager
func NewThreatIntelligenceManager(config *config.Config, logger *logger.Logger) *ThreatIntelligenceManager {
	// Create default alerting config if ThreatIntelligence is nil
	var alertingConfig AlertConfig
	if config.ThreatIntelligence != nil {
		// Convert from config.AlertingConfig to local AlertConfig
		alertingConfig = AlertConfig{
			Enabled: config.ThreatIntelligence.Alerting.Enabled,
			SeverityLevels: []string{"critical", "high", "medium", "low"},
			Channels: config.ThreatIntelligence.Alerting.Channels,
			Throttling: config.ThreatIntelligence.Alerting.Throttling,
			Filters: []AlertFilter{},
		}
	}
	
	return &ThreatIntelligenceManager{
		config:         config,
		feeds:          make(map[string]ThreatFeed),
		threatDatabase: NewThreatDatabase(logger),
		correlator:     NewThreatCorrelator(logger),
		alerting:       NewAlertingSystem(alertingConfig, logger),
		updater:        NewRealTimeUpdater(logger),
		logger:         logger,
		updateInterval: 1 * time.Hour, // Default 1 hour
	}
}

// Initialize sets up the threat intelligence manager
func (tim *ThreatIntelligenceManager) Initialize(ctx context.Context) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()

	tim.logger.Info("Initializing threat intelligence manager")

	// Initialize threat database
	if err := tim.threatDatabase.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize threat database: %w", err)
	}

	// Initialize threat correlator
	if err := tim.correlator.Initialize(ctx, tim.threatDatabase); err != nil {
		return fmt.Errorf("failed to initialize threat correlator: %w", err)
	}

	// Initialize alerting system
	if err := tim.alerting.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize alerting system: %w", err)
	}

	// Initialize real-time updater
	if err := tim.updater.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize real-time updater: %w", err)
	}

	// Initialize threat feeds
	if err := tim.initializeFeeds(ctx); err != nil {
		return fmt.Errorf("failed to initialize threat feeds: %w", err)
	}

	// Load initial threat data
	if err := tim.loadInitialThreats(ctx); err != nil {
		return fmt.Errorf("failed to load initial threats: %w", err)
	}

	tim.isRunning = true
	tim.lastUpdate = time.Now()

	// Start background update process
	go tim.startUpdateLoop(ctx)

	tim.logger.Info("Threat intelligence manager initialized successfully", map[string]interface{}{
		"feeds":           len(tim.feeds),
		"update_interval": tim.updateInterval,
	})

	return nil
}

// CorrelateThreats correlates package information with threat intelligence
func (tim *ThreatIntelligenceManager) CorrelateThreats(ctx context.Context, pkg *types.Package) (*ThreatCorrelationResult, error) {
	tim.mu.RLock()
	defer tim.mu.RUnlock()

	if !tim.isRunning {
		return nil, fmt.Errorf("threat intelligence manager is not running")
	}

	return tim.correlator.CorrelatePackage(ctx, pkg)
}

// UpdateThreats manually triggers a threat intelligence update
func (tim *ThreatIntelligenceManager) UpdateThreats(ctx context.Context) error {
	tim.logger.Info("Manual threat intelligence update triggered")
	return tim.performUpdate(ctx)
}

// GetThreatStatus returns the current status of all threat feeds
func (tim *ThreatIntelligenceManager) GetThreatStatus() map[string]FeedStatus {
	tim.mu.RLock()
	defer tim.mu.RUnlock()

	status := make(map[string]FeedStatus)
	for name, feed := range tim.feeds {
		status[name] = feed.GetStatus()
	}

	return status
}

// GetThreatStatistics returns threat intelligence statistics
func (tim *ThreatIntelligenceManager) GetThreatStatistics() map[string]interface{} {
	tim.mu.RLock()
	defer tim.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_feeds"] = len(tim.feeds)
	stats["last_update"] = tim.lastUpdate
	stats["update_interval"] = tim.updateInterval
	stats["is_running"] = tim.isRunning

	// Get database statistics
	if tim.threatDatabase != nil {
		stats["threat_database"] = tim.threatDatabase.GetStatistics()
	}

	// Get feed statistics
	feedStats := make(map[string]interface{})
	for name, feed := range tim.feeds {
		feedStats[name] = feed.GetStatus()
	}
	stats["feeds"] = feedStats

	return stats
}

// AddCustomThreat adds a custom threat intelligence entry
func (tim *ThreatIntelligenceManager) AddCustomThreat(ctx context.Context, threat *ThreatIntelligence) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()

	threat.Source = "custom"
	threat.FirstSeen = time.Now()
	threat.LastSeen = time.Now()

	if err := tim.threatDatabase.StoreThreat(ctx, threat); err != nil {
		return fmt.Errorf("failed to store custom threat: %w", err)
	}

	tim.logger.Info("Custom threat added", map[string]interface{}{
		"threat_id": threat.ID,
		"package":   threat.PackageName,
	})
	return nil
}

// RemoveThreat removes a threat intelligence entry
func (tim *ThreatIntelligenceManager) RemoveThreat(ctx context.Context, threatID string) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()

	if err := tim.threatDatabase.RemoveThreat(ctx, threatID); err != nil {
		return fmt.Errorf("failed to remove threat: %w", err)
	}

	tim.logger.Info("Threat removed", map[string]interface{}{
		"threat_id": threatID,
	})
	return nil
}

// Shutdown gracefully shuts down the threat intelligence manager
func (tim *ThreatIntelligenceManager) Shutdown(ctx context.Context) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()

	tim.logger.Info("Shutting down threat intelligence manager")
	tim.isRunning = false

	// Close all feeds
	for name, feed := range tim.feeds {
		if err := feed.Close(); err != nil {
			tim.logger.Warn("Failed to close threat feed", map[string]interface{}{
				"feed":  name,
				"error": err,
			})
		}
	}

	// Shutdown components
	if tim.updater != nil {
		tim.updater.Shutdown(ctx)
	}

	if tim.alerting != nil {
		tim.alerting.Shutdown(ctx)
	}

	if tim.threatDatabase != nil {
		tim.threatDatabase.Close()
	}

	tim.logger.Info("Threat intelligence manager shutdown completed")
	return nil
}

// Helper methods

func (tim *ThreatIntelligenceManager) initializeFeeds(ctx context.Context) error {
	// Check if ThreatIntelligence configuration exists
	if tim.config.ThreatIntelligence == nil {
		tim.logger.Info("No threat intelligence configuration found, skipping feed initialization")
		return nil
	}
	
	// Initialize OSV feed if enabled
	if tim.config.ThreatIntelligence.Feeds != nil {
		// For now, create basic feeds without specific configuration
		// TODO: Implement proper feed configuration structure
		osvFeed := NewOSVFeed(tim.logger)
		if err := osvFeed.Initialize(ctx, map[string]interface{}{
			"update_interval": 1 * time.Hour,
		}); err != nil {
			return fmt.Errorf("failed to initialize OSV feed: %w", err)
		}
		tim.feeds["osv"] = osvFeed
		
		// Initialize GitHub Advisory feed
		ghFeed := NewGitHubAdvisoryFeed(tim.logger)
		if err := ghFeed.Initialize(ctx, map[string]interface{}{
			"update_interval": 1 * time.Hour,
		}); err != nil {
			return fmt.Errorf("failed to initialize GitHub Advisory feed: %w", err)
		}
		tim.feeds["github_advisory"] = ghFeed
	}

	return nil
}

func (tim *ThreatIntelligenceManager) loadInitialThreats(ctx context.Context) error {
	tim.logger.Info("Loading initial threat intelligence data")

	for name, feed := range tim.feeds {
		tim.logger.Debug("Loading threats from feed", map[string]interface{}{
			"feed": name,
		})
		
		// Load threats from the beginning of time for initial load
		threats, err := feed.FetchThreats(ctx, time.Time{})
		if err != nil {
			tim.logger.Warn("Failed to load initial threats from feed", map[string]interface{}{
				"feed":  name,
				"error": err,
			})
			continue
		}

		// Store threats in database
		for _, threat := range threats {
			if err := tim.threatDatabase.StoreThreat(ctx, &threat); err != nil {
				tim.logger.Warn("Failed to store threat", map[string]interface{}{
					"threat_id": threat.ID,
					"error":     err,
				})
			}
		}

		tim.logger.Info("Loaded threats from feed", map[string]interface{}{
			"feed":  name,
			"count": len(threats),
		})
	}

	return nil
}

func (tim *ThreatIntelligenceManager) startUpdateLoop(ctx context.Context) {
	ticker := time.NewTicker(tim.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if tim.isRunning {
				if err := tim.performUpdate(ctx); err != nil {
					tim.logger.Error("Threat intelligence update failed", map[string]interface{}{
				"error": err,
			})
				}
			}
		}
	}
}

func (tim *ThreatIntelligenceManager) performUpdate(ctx context.Context) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()

	start := time.Now()
	tim.logger.Debug("Starting threat intelligence update")

	totalNewThreats := 0

	for name, feed := range tim.feeds {
		// Fetch new threats since last update
		threats, err := feed.FetchThreats(ctx, tim.lastUpdate)
		if err != nil {
			tim.logger.Warn("Failed to fetch threats from feed", map[string]interface{}{
				"feed":  name,
				"error": err,
			})
			continue
		}

		// Store new threats
		newThreats := 0
		for _, threat := range threats {
			if err := tim.threatDatabase.StoreThreat(ctx, &threat); err != nil {
				tim.logger.Warn("Failed to store threat", map[string]interface{}{
					"threat_id": threat.ID,
					"error":     err,
				})
				continue
			}
			newThreats++

			// Send alert for high-severity threats
			if threat.Severity == "critical" || threat.Severity == "high" {
				go tim.alerting.SendThreatAlert(ctx, &threat)
			}
		}

		totalNewThreats += newThreats
		tim.logger.Debug("Updated threats from feed", map[string]interface{}{
			"feed":        name,
			"new_threats": newThreats,
		})
	}

	tim.lastUpdate = start

	tim.logger.Info("Threat intelligence update completed", map[string]interface{}{
		"duration":    time.Since(start),
		"new_threats": totalNewThreats,
		"total_feeds": len(tim.feeds),
	})

	return nil
}