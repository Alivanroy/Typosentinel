package threat_intelligence

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// RealTimeUpdater manages real-time threat intelligence updates
type RealTimeUpdater struct {
	logger         *logger.Logger
	mu             sync.RWMutex
	updateChannels map[string]*UpdateChannel
	subscribers    map[string][]UpdateSubscriber
	isRunning      bool
	updateInterval time.Duration
	lastUpdate     time.Time
	updateStats    UpdateStats
	errorHandler   ErrorHandler
	config         UpdaterConfig
}

// UpdateChannel represents a real-time update channel
type UpdateChannel struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // "webhook", "polling", "stream", "feed"
	Enabled     bool                   `json:"enabled"`
	Config      map[string]interface{} `json:"config"`
	LastUpdate  time.Time              `json:"last_update"`
	UpdateCount int64                  `json:"update_count"`
	ErrorCount  int64                  `json:"error_count"`
	Status      string                 `json:"status"` // "active", "inactive", "error"
	Healthy     bool                   `json:"healthy"`
	Processor   UpdateProcessor        `json:"-"`
}

// UpdateProcessor processes updates from a specific channel
type UpdateProcessor interface {
	// Initialize sets up the processor
	Initialize(ctx context.Context, config map[string]interface{}) error

	// Start begins processing updates
	Start(ctx context.Context) error

	// Stop stops processing updates
	Stop(ctx context.Context) error

	// GetStatus returns processor status
	GetStatus() ProcessorStatus

	// SetUpdateHandler sets the update handler
	SetUpdateHandler(handler UpdateHandler)
}

// UpdateSubscriber receives update notifications
type UpdateSubscriber interface {
	// OnUpdate is called when an update is received
	OnUpdate(ctx context.Context, update *ThreatUpdate) error

	// GetSubscriberID returns the subscriber ID
	GetSubscriberID() string
}

// ThreatUpdate represents a threat intelligence update
type ThreatUpdate struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Type      string                 `json:"type"` // "new", "updated", "removed"
	Threat    *ThreatIntelligence    `json:"threat,omitempty"`
	ThreatID  string                 `json:"threat_id,omitempty"`
	Changes   map[string]interface{} `json:"changes,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	Priority  string                 `json:"priority"` // "low", "medium", "high", "critical"
	Checksum  string                 `json:"checksum"`
}

// UpdateHandler handles threat updates
type UpdateHandler func(ctx context.Context, update *ThreatUpdate) error

// ProcessorStatus represents the status of an update processor
type ProcessorStatus struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	Running     bool          `json:"running"`
	Healthy     bool          `json:"healthy"`
	LastUpdate  time.Time     `json:"last_update"`
	LastError   string        `json:"last_error,omitempty"`
	UpdateCount int64         `json:"update_count"`
	ErrorCount  int64         `json:"error_count"`
	Latency     time.Duration `json:"latency"`
}

// UpdateStats represents update statistics
type UpdateStats struct {
	TotalUpdates      int64                     `json:"total_updates"`
	UpdatesByType     map[string]int64          `json:"updates_by_type"`
	UpdatesBySource   map[string]int64          `json:"updates_by_source"`
	UpdatesByPriority map[string]int64          `json:"updates_by_priority"`
	FailedUpdates     int64                     `json:"failed_updates"`
	LastUpdate        time.Time                 `json:"last_update"`
	AverageLatency    time.Duration             `json:"average_latency"`
	ChannelStats      map[string]*UpdateChannel `json:"channel_stats"`
}

// UpdaterConfig represents updater configuration
type UpdaterConfig struct {
	Enabled        bool                  `json:"enabled"`
	UpdateInterval time.Duration         `json:"update_interval"`
	MaxConcurrent  int                   `json:"max_concurrent"`
	RetryAttempts  int                   `json:"retry_attempts"`
	RetryDelay     time.Duration         `json:"retry_delay"`
	Channels       []UpdateChannelConfig `json:"channels"`
	ErrorHandling  ErrorHandlingConfig   `json:"error_handling"`
}

// UpdateChannelConfig represents update channel configuration
type UpdateChannelConfig struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Enabled  bool                   `json:"enabled"`
	Config   map[string]interface{} `json:"config"`
	Priority int                    `json:"priority"`
}

// ErrorHandlingConfig represents error handling configuration
type ErrorHandlingConfig struct {
	MaxErrors       int           `json:"max_errors"`
	ErrorWindow     time.Duration `json:"error_window"`
	BackoffStrategy string        `json:"backoff_strategy"` // "linear", "exponential"
	MaxBackoff      time.Duration `json:"max_backoff"`
	AlertOnError    bool          `json:"alert_on_error"`
}

// ErrorHandler handles update errors
type ErrorHandler func(ctx context.Context, channel string, err error)

// NewRealTimeUpdater creates a new real-time updater
func NewRealTimeUpdater(logger *logger.Logger) *RealTimeUpdater {
	return &RealTimeUpdater{
		logger:         logger,
		updateChannels: make(map[string]*UpdateChannel),
		subscribers:    make(map[string][]UpdateSubscriber),
		updateInterval: 5 * time.Minute,
		updateStats: UpdateStats{
			UpdatesByType:     make(map[string]int64),
			UpdatesBySource:   make(map[string]int64),
			UpdatesByPriority: make(map[string]int64),
			ChannelStats:      make(map[string]*UpdateChannel),
		},
		config: UpdaterConfig{
			Enabled:       true,
			MaxConcurrent: 10,
			RetryAttempts: 3,
			RetryDelay:    30 * time.Second,
		},
	}
}

// Initialize sets up the real-time updater
func (rtu *RealTimeUpdater) Initialize(ctx context.Context) error {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	rtu.logger.Info("Initializing real-time updater")

	// Set default error handler
	if rtu.errorHandler == nil {
		rtu.errorHandler = rtu.defaultErrorHandler
	}

	// Initialize update channels
	for _, channelConfig := range rtu.config.Channels {
		if !channelConfig.Enabled {
			continue
		}

		if err := rtu.addUpdateChannel(ctx, channelConfig); err != nil {
			rtu.logger.Warn("Failed to add update channel", map[string]interface{}{"channel": channelConfig.Name, "error": err})
			continue
		}
	}

	rtu.logger.Info("Real-time updater initialized", map[string]interface{}{"channels": len(rtu.updateChannels)})
	return nil
}

// Start begins real-time updates
func (rtu *RealTimeUpdater) Start(ctx context.Context) error {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	if rtu.isRunning {
		return fmt.Errorf("real-time updater is already running")
	}

	rtu.logger.Info("Starting real-time updater")

	// Start all update channels
	for name, channel := range rtu.updateChannels {
		if !channel.Enabled {
			continue
		}

		if err := channel.Processor.Start(ctx); err != nil {
			rtu.logger.Warn("Failed to start update channel", map[string]interface{}{"channel": name, "error": err})
			channel.Status = "error"
			channel.Healthy = false
			continue
		}

		channel.Status = "active"
		channel.Healthy = true
		rtu.logger.Info("Update channel started", map[string]interface{}{"channel": name})
	}

	rtu.isRunning = true
	rtu.lastUpdate = time.Now()

	// Start monitoring routine
	go rtu.startMonitoring(ctx)

	rtu.logger.Info("Real-time updater started successfully")
	return nil
}

// Stop stops real-time updates
func (rtu *RealTimeUpdater) Stop(ctx context.Context) error {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	if !rtu.isRunning {
		return nil
	}

	rtu.logger.Info("Stopping real-time updater")

	// Stop all update channels
	for name, channel := range rtu.updateChannels {
		if err := channel.Processor.Stop(ctx); err != nil {
			rtu.logger.Warn("Failed to stop update channel", map[string]interface{}{"channel": name, "error": err})
		}
		channel.Status = "inactive"
	}

	rtu.isRunning = false
	rtu.logger.Info("Real-time updater stopped")
	return nil
}

// Subscribe adds a subscriber for updates
func (rtu *RealTimeUpdater) Subscribe(source string, subscriber UpdateSubscriber) error {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	rtu.subscribers[source] = append(rtu.subscribers[source], subscriber)
	rtu.logger.Info("Subscriber added", map[string]interface{}{"source": source, "subscriber_id": subscriber.GetSubscriberID()})
	return nil
}

// Unsubscribe removes a subscriber
func (rtu *RealTimeUpdater) Unsubscribe(source string, subscriberID string) error {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	subscribers := rtu.subscribers[source]
	for i, sub := range subscribers {
		if sub.GetSubscriberID() == subscriberID {
			rtu.subscribers[source] = append(subscribers[:i], subscribers[i+1:]...)
			rtu.logger.Info("Subscriber removed", map[string]interface{}{"source": source, "subscriber_id": subscriberID})
			return nil
		}
	}

	return fmt.Errorf("subscriber not found: %s", subscriberID)
}

// ProcessUpdate processes a threat intelligence update
func (rtu *RealTimeUpdater) ProcessUpdate(ctx context.Context, update *ThreatUpdate) error {
	start := time.Now()

	rtu.logger.Debug("Processing threat update", map[string]interface{}{
		"update_id": update.ID,
		"source":    update.Source,
		"type":      update.Type,
		"priority":  update.Priority,
	})

	// Update statistics
	rtu.recordUpdateStats(update)

	// Notify subscribers
	if err := rtu.notifySubscribers(ctx, update); err != nil {
		rtu.logger.Warn("Failed to notify some subscribers", map[string]interface{}{"update_id": update.ID, "error": err})
	}

	// Update latency statistics
	latency := time.Since(start)
	rtu.updateLatencyStats(latency)

	rtu.logger.Debug("Threat update processed", map[string]interface{}{
		"update_id": update.ID,
		"latency":   latency,
	})

	return nil
}

// AddUpdateChannel adds a new update channel
func (rtu *RealTimeUpdater) AddUpdateChannel(ctx context.Context, config UpdateChannelConfig) error {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	return rtu.addUpdateChannel(ctx, config)
}

// RemoveUpdateChannel removes an update channel
func (rtu *RealTimeUpdater) RemoveUpdateChannel(ctx context.Context, name string) error {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	channel, exists := rtu.updateChannels[name]
	if !exists {
		return fmt.Errorf("update channel not found: %s", name)
	}

	// Stop the channel if running
	if channel.Status == "active" {
		if err := channel.Processor.Stop(ctx); err != nil {
			rtu.logger.Warn("Failed to stop update channel", map[string]interface{}{"channel": name, "error": err})
		}
	}

	delete(rtu.updateChannels, name)
	rtu.logger.Info("Update channel removed", map[string]interface{}{"channel": name})
	return nil
}

// GetStatistics returns update statistics
func (rtu *RealTimeUpdater) GetStatistics() UpdateStats {
	rtu.mu.RLock()
	defer rtu.mu.RUnlock()

	// Update channel stats
	for name, channel := range rtu.updateChannels {
		rtu.updateStats.ChannelStats[name] = channel
	}

	return rtu.updateStats
}

// GetChannelStatus returns the status of all update channels
func (rtu *RealTimeUpdater) GetChannelStatus() map[string]ProcessorStatus {
	rtu.mu.RLock()
	defer rtu.mu.RUnlock()

	status := make(map[string]ProcessorStatus)
	for name, channel := range rtu.updateChannels {
		status[name] = channel.Processor.GetStatus()
	}

	return status
}

// UpdateConfiguration updates the updater configuration
func (rtu *RealTimeUpdater) UpdateConfiguration(config UpdaterConfig) error {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	rtu.config = config
	rtu.updateInterval = config.UpdateInterval

	rtu.logger.Info("Real-time updater configuration updated")
	return nil
}

// Shutdown gracefully shuts down the updater
func (rtu *RealTimeUpdater) Shutdown(ctx context.Context) error {
	rtu.logger.Info("Shutting down real-time updater")

	// Stop all channels
	if err := rtu.Stop(ctx); err != nil {
		rtu.logger.Warn("Error stopping updater", map[string]interface{}{"error": err})
	}

	rtu.logger.Info("Real-time updater shutdown completed")
	return nil
}

// Helper methods

func (rtu *RealTimeUpdater) addUpdateChannel(ctx context.Context, config UpdateChannelConfig) error {
	processor, err := rtu.createProcessor(config.Type)
	if err != nil {
		return fmt.Errorf("failed to create processor for channel %s: %w", config.Name, err)
	}

	// Set update handler
	processor.SetUpdateHandler(rtu.ProcessUpdate)

	// Initialize processor
	if err := processor.Initialize(ctx, config.Config); err != nil {
		return fmt.Errorf("failed to initialize processor for channel %s: %w", config.Name, err)
	}

	channel := &UpdateChannel{
		Name:      config.Name,
		Type:      config.Type,
		Enabled:   config.Enabled,
		Config:    config.Config,
		Status:    "inactive",
		Healthy:   true,
		Processor: processor,
	}

	rtu.updateChannels[config.Name] = channel
	rtu.logger.Info("Update channel added", map[string]interface{}{"channel": config.Name, "type": config.Type})
	return nil
}

func (rtu *RealTimeUpdater) createProcessor(processorType string) (UpdateProcessor, error) {
	switch processorType {
	case "webhook":
		return NewWebhookProcessor(rtu.logger), nil
	case "polling":
		return NewPollingProcessor(rtu.logger), nil
	case "stream":
		return NewStreamProcessor(rtu.logger), nil
	case "feed":
		return NewFeedProcessor(rtu.logger), nil
	default:
		return nil, fmt.Errorf("unsupported processor type: %s", processorType)
	}
}

func (rtu *RealTimeUpdater) notifySubscribers(ctx context.Context, update *ThreatUpdate) error {
	subscribers := rtu.subscribers[update.Source]
	if len(subscribers) == 0 {
		// Also notify "all" subscribers
		subscribers = rtu.subscribers["all"]
	}

	var errors []string
	for _, subscriber := range subscribers {
		if err := subscriber.OnUpdate(ctx, update); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", subscriber.GetSubscriberID(), err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("subscriber errors: %v", errors)
	}

	return nil
}

func (rtu *RealTimeUpdater) recordUpdateStats(update *ThreatUpdate) {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	rtu.updateStats.TotalUpdates++
	rtu.updateStats.UpdatesByType[update.Type]++
	rtu.updateStats.UpdatesBySource[update.Source]++
	rtu.updateStats.UpdatesByPriority[update.Priority]++
	rtu.updateStats.LastUpdate = time.Now()

	// Update channel stats
	if channel, exists := rtu.updateChannels[update.Source]; exists {
		channel.UpdateCount++
		channel.LastUpdate = time.Now()
	}
}

func (rtu *RealTimeUpdater) updateLatencyStats(latency time.Duration) {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	// Simple moving average for latency
	if rtu.updateStats.AverageLatency == 0 {
		rtu.updateStats.AverageLatency = latency
	} else {
		rtu.updateStats.AverageLatency = (rtu.updateStats.AverageLatency + latency) / 2
	}
}

func (rtu *RealTimeUpdater) startMonitoring(ctx context.Context) {
	ticker := time.NewTicker(rtu.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if rtu.isRunning {
				rtu.performHealthCheck()
			}
		}
	}
}

func (rtu *RealTimeUpdater) performHealthCheck() {
	rtu.mu.Lock()
	defer rtu.mu.Unlock()

	for name, channel := range rtu.updateChannels {
		status := channel.Processor.GetStatus()

		// Update channel health based on processor status
		channel.Healthy = status.Healthy
		channel.ErrorCount = status.ErrorCount

		if !status.Healthy {
			channel.Status = "error"
			rtu.logger.Warn("Update channel unhealthy", map[string]interface{}{"channel": name, "error": status.LastError})

			// Call error handler
			if rtu.errorHandler != nil {
				go rtu.errorHandler(context.Background(), name, fmt.Errorf(status.LastError))
			}
		} else if channel.Status == "error" {
			channel.Status = "active"
			rtu.logger.Info("Update channel recovered", map[string]interface{}{"channel": name})
		}
	}
}

func (rtu *RealTimeUpdater) defaultErrorHandler(ctx context.Context, channel string, err error) {
	rtu.logger.Error("Update channel error", map[string]interface{}{"channel": channel, "error": err})

	// Update error statistics
	rtu.mu.Lock()
	rtu.updateStats.FailedUpdates++
	if ch, exists := rtu.updateChannels[channel]; exists {
		ch.ErrorCount++
	}
	rtu.mu.Unlock()
}

// Processor implementations (simplified)

// WebhookProcessor processes webhook updates
type WebhookProcessor struct {
	logger        *logger.Logger
	updateHandler UpdateHandler
	status        ProcessorStatus
	config        map[string]interface{}
}

func NewWebhookProcessor(logger *logger.Logger) *WebhookProcessor {
	return &WebhookProcessor{
		logger: logger,
		status: ProcessorStatus{
			Name:    "webhook",
			Type:    "webhook",
			Healthy: true,
		},
	}
}

func (wp *WebhookProcessor) Initialize(ctx context.Context, config map[string]interface{}) error {
	wp.config = config
	return nil
}

func (wp *WebhookProcessor) Start(ctx context.Context) error {
	wp.status.Running = true
	return nil
}

func (wp *WebhookProcessor) Stop(ctx context.Context) error {
	wp.status.Running = false
	return nil
}

func (wp *WebhookProcessor) GetStatus() ProcessorStatus {
	return wp.status
}

func (wp *WebhookProcessor) SetUpdateHandler(handler UpdateHandler) {
	wp.updateHandler = handler
}

// PollingProcessor processes updates via polling
type PollingProcessor struct {
	logger        *logger.Logger
	updateHandler UpdateHandler
	status        ProcessorStatus
	config        map[string]interface{}
}

func NewPollingProcessor(logger *logger.Logger) *PollingProcessor {
	return &PollingProcessor{
		logger: logger,
		status: ProcessorStatus{
			Name:    "polling",
			Type:    "polling",
			Healthy: true,
		},
	}
}

func (pp *PollingProcessor) Initialize(ctx context.Context, config map[string]interface{}) error {
	pp.config = config
	return nil
}

func (pp *PollingProcessor) Start(ctx context.Context) error {
	pp.status.Running = true
	return nil
}

func (pp *PollingProcessor) Stop(ctx context.Context) error {
	pp.status.Running = false
	return nil
}

func (pp *PollingProcessor) GetStatus() ProcessorStatus {
	return pp.status
}

func (pp *PollingProcessor) SetUpdateHandler(handler UpdateHandler) {
	pp.updateHandler = handler
}

// StreamProcessor processes streaming updates
type StreamProcessor struct {
	logger        *logger.Logger
	updateHandler UpdateHandler
	status        ProcessorStatus
	config        map[string]interface{}
}

func NewStreamProcessor(logger *logger.Logger) *StreamProcessor {
	return &StreamProcessor{
		logger: logger,
		status: ProcessorStatus{
			Name:    "stream",
			Type:    "stream",
			Healthy: true,
		},
	}
}

func (sp *StreamProcessor) Initialize(ctx context.Context, config map[string]interface{}) error {
	sp.config = config
	return nil
}

func (sp *StreamProcessor) Start(ctx context.Context) error {
	sp.status.Running = true
	return nil
}

func (sp *StreamProcessor) Stop(ctx context.Context) error {
	sp.status.Running = false
	return nil
}

func (sp *StreamProcessor) GetStatus() ProcessorStatus {
	return sp.status
}

func (sp *StreamProcessor) SetUpdateHandler(handler UpdateHandler) {
	sp.updateHandler = handler
}

// FeedProcessor processes feed updates
type FeedProcessor struct {
	logger        *logger.Logger
	updateHandler UpdateHandler
	status        ProcessorStatus
	config        map[string]interface{}
}

func NewFeedProcessor(logger *logger.Logger) *FeedProcessor {
	return &FeedProcessor{
		logger: logger,
		status: ProcessorStatus{
			Name:    "feed",
			Type:    "feed",
			Healthy: true,
		},
	}
}

func (fp *FeedProcessor) Initialize(ctx context.Context, config map[string]interface{}) error {
	fp.config = config
	return nil
}

func (fp *FeedProcessor) Start(ctx context.Context) error {
	fp.status.Running = true
	return nil
}

func (fp *FeedProcessor) Stop(ctx context.Context) error {
	fp.status.Running = false
	return nil
}

func (fp *FeedProcessor) GetStatus() ProcessorStatus {
	return fp.status
}

func (fp *FeedProcessor) SetUpdateHandler(handler UpdateHandler) {
	fp.updateHandler = handler
}
