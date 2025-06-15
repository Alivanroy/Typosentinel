package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/typosentinel/typosentinel/pkg/metrics"
)

// EventType defines the type of event
type EventType string

const (
	// Scan events
	EventTypeScanStarted   EventType = "scan.started"
	EventTypeScanCompleted EventType = "scan.completed"
	EventTypeScanFailed    EventType = "scan.failed"
	EventTypeScanProgress  EventType = "scan.progress"

	// Batch events
	EventTypeBatchCreated   EventType = "batch.created"
	EventTypeBatchStarted   EventType = "batch.started"
	EventTypeBatchCompleted EventType = "batch.completed"
	EventTypeBatchFailed    EventType = "batch.failed"
	EventTypeBatchProgress  EventType = "batch.progress"
	EventTypeBatchCancelled EventType = "batch.cancelled"

	// Worker events
	EventTypeWorkerStarted EventType = "worker.started"
	EventTypeWorkerStopped EventType = "worker.stopped"
	EventTypeWorkerFailed  EventType = "worker.failed"
	EventTypeWorkerScaled  EventType = "worker.scaled"

	// System events
	EventTypeSystemAlert     EventType = "system.alert"
	EventTypeSystemHealth    EventType = "system.health"
	EventTypeSystemMetrics   EventType = "system.metrics"
	EventTypeSystemShutdown  EventType = "system.shutdown"
	EventTypeSystemStartup   EventType = "system.startup"

	// Configuration events
	EventTypeConfigChanged EventType = "config.changed"
	EventTypeConfigReload  EventType = "config.reload"

	// Cache events
	EventTypeCacheHit   EventType = "cache.hit"
	EventTypeCacheMiss  EventType = "cache.miss"
	EventTypeCacheEvict EventType = "cache.evict"

	// Queue events
	EventTypeQueueMessage EventType = "queue.message"
	EventTypeQueueError   EventType = "queue.error"

	// Load balancer events
	EventTypeBackendAdded   EventType = "loadbalancer.backend.added"
	EventTypeBackendRemoved EventType = "loadbalancer.backend.removed"
	EventTypeBackendHealthy EventType = "loadbalancer.backend.healthy"
	EventTypeBackendUnhealthy EventType = "loadbalancer.backend.unhealthy"

	// Auto scaler events
	EventTypeScaleUp   EventType = "autoscaler.scale.up"
	EventTypeScaleDown EventType = "autoscaler.scale.down"
	EventTypeScaleEvent EventType = "autoscaler.scale.event"
)

// EventPriority defines the priority of an event
type EventPriority int

const (
	EventPriorityLow EventPriority = iota
	EventPriorityNormal
	EventPriorityHigh
	EventPriorityCritical
)

func (ep EventPriority) String() string {
	switch ep {
	case EventPriorityLow:
		return "low"
	case EventPriorityNormal:
		return "normal"
	case EventPriorityHigh:
		return "high"
	case EventPriorityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Event represents an event in the system
type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Source    string                 `json:"source"`
	Target    string                 `json:"target,omitempty"`
	Data      map[string]interface{} `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Priority  EventPriority          `json:"priority"`
	Timestamp time.Time              `json:"timestamp"`
	TTL       time.Duration          `json:"ttl,omitempty"`
	Retries   int                    `json:"retries"`
	MaxRetries int                   `json:"max_retries"`
}

// EventHandler defines the interface for event handlers
type EventHandler interface {
	HandleEvent(ctx context.Context, event *Event) error
	GetEventTypes() []EventType
	GetHandlerID() string
}

// EventFilter defines the interface for event filters
type EventFilter interface {
	ShouldProcess(event *Event) bool
	GetFilterID() string
}

// EventMiddleware defines the interface for event middleware
type EventMiddleware interface {
	Process(ctx context.Context, event *Event, next func(context.Context, *Event) error) error
	GetMiddlewareID() string
}

// Subscription represents an event subscription
type Subscription struct {
	ID         string        `json:"id"`
	EventTypes []EventType   `json:"event_types"`
	Handler    EventHandler  `json:"-"`
	Filters    []EventFilter `json:"-"`
	CreatedAt  time.Time     `json:"created_at"`
	Active     bool          `json:"active"`
}

// EventBus manages event publishing and subscription
type EventBus struct {
	subscriptions map[string]*Subscription
	middleware    []EventMiddleware
	redis         *redis.Client
	metrics       *metrics.Metrics
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.RWMutex
	middlewareMu  sync.RWMutex
	config        *EventBusConfig
	running       bool
	eventHistory  []*Event
	historyMu     sync.RWMutex
	maxHistorySize int
	workerPool    chan struct{}
}

// EventBusConfig holds configuration for the event bus
type EventBusConfig struct {
	RedisChannel       string        `json:"redis_channel"`
	RedisKeyPrefix     string        `json:"redis_key_prefix"`
	MaxWorkers         int           `json:"max_workers"`
	MaxHistorySize     int           `json:"max_history_size"`
	DefaultTTL         time.Duration `json:"default_ttl"`
	MaxRetries         int           `json:"max_retries"`
	RetryDelay         time.Duration `json:"retry_delay"`
	EnableRedisSync    bool          `json:"enable_redis_sync"`
	EnableMetrics      bool          `json:"enable_metrics"`
	EnableHistory      bool          `json:"enable_history"`
	BufferSize         int           `json:"buffer_size"`
	ProcessingTimeout  time.Duration `json:"processing_timeout"`
}

// EventStats holds event bus statistics
type EventStats struct {
	TotalEvents     int64 `json:"total_events"`
	ProcessedEvents int64 `json:"processed_events"`
	FailedEvents    int64 `json:"failed_events"`
	ActiveHandlers  int   `json:"active_handlers"`
	QueuedEvents    int   `json:"queued_events"`
}

// NewEventBus creates a new event bus
func NewEventBus(config *EventBusConfig, redis *redis.Client) *EventBus {
	ctx, cancel := context.WithCancel(context.Background())

	// Set default values
	if config.RedisChannel == "" {
		config.RedisChannel = "typosentinel:events"
	}
	if config.RedisKeyPrefix == "" {
		config.RedisKeyPrefix = "typosentinel:events:"
	}
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 10
	}
	if config.MaxHistorySize == 0 {
		config.MaxHistorySize = 1000
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 24 * time.Hour
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5 * time.Second
	}
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	if config.ProcessingTimeout == 0 {
		config.ProcessingTimeout = 30 * time.Second
	}

	return &EventBus{
		subscriptions:  make(map[string]*Subscription),
		middleware:     make([]EventMiddleware, 0),
		redis:          redis,
		metrics:        metrics.GetInstance(),
		ctx:            ctx,
		cancel:         cancel,
		config:         config,
		eventHistory:   make([]*Event, 0, config.MaxHistorySize),
		maxHistorySize: config.MaxHistorySize,
		workerPool:     make(chan struct{}, config.MaxWorkers),
	}
}

// Start starts the event bus
func (eb *EventBus) Start() error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.running {
		return fmt.Errorf("event bus is already running")
	}

	// Initialize worker pool
	for i := 0; i < eb.config.MaxWorkers; i++ {
		eb.workerPool <- struct{}{}
	}

	// Start Redis subscriber if enabled
	if eb.config.EnableRedisSync && eb.redis != nil {
		go eb.redisSubscriber()
	}

	eb.running = true
	log.Printf("Event bus started with %d workers", eb.config.MaxWorkers)
	return nil
}

// Stop stops the event bus
func (eb *EventBus) Stop() error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if !eb.running {
		return fmt.Errorf("event bus is not running")
	}

	eb.cancel()
	eb.running = false
	log.Println("Event bus stopped")
	return nil
}

// Publish publishes an event
func (eb *EventBus) Publish(ctx context.Context, event *Event) error {
	if event.ID == "" {
		event.ID = eb.generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.TTL == 0 {
		event.TTL = eb.config.DefaultTTL
	}
	if event.MaxRetries == 0 {
		event.MaxRetries = eb.config.MaxRetries
	}
	if event.Data == nil {
		event.Data = make(map[string]interface{})
	}
	if event.Metadata == nil {
		event.Metadata = make(map[string]interface{})
	}

	// Add metadata
	event.Metadata["published_at"] = time.Now()
	event.Metadata["bus_id"] = "main"

	// Record in history if enabled
	if eb.config.EnableHistory {
		eb.recordEvent(event)
	}

	// Update metrics
	if eb.config.EnableMetrics {
		eb.metrics.EventsPublished.WithLabelValues(string(event.Type), event.Source).Inc()
	}

	// Publish to Redis if enabled
	if eb.config.EnableRedisSync && eb.redis != nil {
		go eb.publishToRedis(event)
	}

	// Process locally
	go eb.processEvent(ctx, event)

	log.Printf("Published event: %s (type: %s, source: %s)", event.ID, event.Type, event.Source)
	return nil
}

// Subscribe subscribes to events
func (eb *EventBus) Subscribe(handler EventHandler, filters ...EventFilter) (*Subscription, error) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	subscription := &Subscription{
		ID:         eb.generateSubscriptionID(),
		EventTypes: handler.GetEventTypes(),
		Handler:    handler,
		Filters:    filters,
		CreatedAt:  time.Now(),
		Active:     true,
	}

	eb.subscriptions[subscription.ID] = subscription

	log.Printf("Added subscription: %s (handler: %s, types: %v)",
		subscription.ID, handler.GetHandlerID(), handler.GetEventTypes())

	return subscription, nil
}

// Unsubscribe removes a subscription
func (eb *EventBus) Unsubscribe(subscriptionID string) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	subscription, exists := eb.subscriptions[subscriptionID]
	if !exists {
		return fmt.Errorf("subscription not found: %s", subscriptionID)
	}

	subscription.Active = false
	delete(eb.subscriptions, subscriptionID)

	log.Printf("Removed subscription: %s", subscriptionID)
	return nil
}

// AddMiddleware adds event middleware
func (eb *EventBus) AddMiddleware(middleware EventMiddleware) {
	eb.middlewareMu.Lock()
	defer eb.middlewareMu.Unlock()

	eb.middleware = append(eb.middleware, middleware)
	log.Printf("Added middleware: %s", middleware.GetMiddlewareID())
}

// RemoveMiddleware removes event middleware
func (eb *EventBus) RemoveMiddleware(middlewareID string) error {
	eb.middlewareMu.Lock()
	defer eb.middlewareMu.Unlock()

	for i, middleware := range eb.middleware {
		if middleware.GetMiddlewareID() == middlewareID {
			eb.middleware = append(eb.middleware[:i], eb.middleware[i+1:]...)
			log.Printf("Removed middleware: %s", middlewareID)
			return nil
		}
	}

	return fmt.Errorf("middleware not found: %s", middlewareID)
}

// processEvent processes an event through all matching handlers
func (eb *EventBus) processEvent(ctx context.Context, event *Event) {
	// Get a worker from the pool
	<-eb.workerPool
	defer func() {
		eb.workerPool <- struct{}{}
	}()

	// Create processing context with timeout
	processCtx, cancel := context.WithTimeout(ctx, eb.config.ProcessingTimeout)
	defer cancel()

	// Find matching subscriptions
	matchingSubscriptions := eb.findMatchingSubscriptions(event)

	if len(matchingSubscriptions) == 0 {
		log.Printf("No handlers found for event: %s (type: %s)", event.ID, event.Type)
		return
	}

	// Process through each matching subscription
	for _, subscription := range matchingSubscriptions {
		if !subscription.Active {
			continue
		}

		// Apply filters
		if !eb.applyFilters(event, subscription.Filters) {
			continue
		}

		// Process through middleware chain
		err := eb.processWithMiddleware(processCtx, event, subscription.Handler)
		if err != nil {
			log.Printf("Error processing event %s with handler %s: %v",
				event.ID, subscription.Handler.GetHandlerID(), err)

			// Update metrics
			if eb.config.EnableMetrics {
				eb.metrics.EventsProcessingFailed.WithLabelValues(
					string(event.Type),
					subscription.Handler.GetHandlerID(),
				).Inc()
			}

			// Retry if configured
			if event.Retries < event.MaxRetries {
				go eb.retryEvent(ctx, event, subscription)
			}
		} else {
			// Update metrics
			if eb.config.EnableMetrics {
				eb.metrics.EventsProcessed.WithLabelValues(
					string(event.Type),
					subscription.Handler.GetHandlerID(),
				).Inc()
			}
		}
	}
}

// findMatchingSubscriptions finds subscriptions that match the event
func (eb *EventBus) findMatchingSubscriptions(event *Event) []*Subscription {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	var matching []*Subscription

	for _, subscription := range eb.subscriptions {
		if !subscription.Active {
			continue
		}

		// Check if event type matches
		for _, eventType := range subscription.EventTypes {
			if eventType == event.Type {
				matching = append(matching, subscription)
				break
			}
		}
	}

	return matching
}

// applyFilters applies filters to determine if event should be processed
func (eb *EventBus) applyFilters(event *Event, filters []EventFilter) bool {
	for _, filter := range filters {
		if !filter.ShouldProcess(event) {
			return false
		}
	}
	return true
}

// processWithMiddleware processes event through middleware chain
func (eb *EventBus) processWithMiddleware(ctx context.Context, event *Event, handler EventHandler) error {
	eb.middlewareMu.RLock()
	middleware := make([]EventMiddleware, len(eb.middleware))
	copy(middleware, eb.middleware)
	eb.middlewareMu.RUnlock()

	// Create middleware chain
	var next func(context.Context, *Event) error
	next = func(ctx context.Context, event *Event) error {
		return handler.HandleEvent(ctx, event)
	}

	// Apply middleware in reverse order
	for i := len(middleware) - 1; i >= 0; i-- {
		mw := middleware[i]
		currentNext := next
		next = func(ctx context.Context, event *Event) error {
			return mw.Process(ctx, event, currentNext)
		}
	}

	return next(ctx, event)
}

// retryEvent retries processing an event
func (eb *EventBus) retryEvent(ctx context.Context, event *Event, subscription *Subscription) {
	time.Sleep(eb.config.RetryDelay)

	event.Retries++
	event.Metadata["retry_count"] = event.Retries
	event.Metadata["last_retry"] = time.Now()

	log.Printf("Retrying event %s (attempt %d/%d)", event.ID, event.Retries, event.MaxRetries)

	// Process through middleware chain
	err := eb.processWithMiddleware(ctx, event, subscription.Handler)
	if err != nil {
		log.Printf("Retry failed for event %s: %v", event.ID, err)

		// Try again if retries remaining
		if event.Retries < event.MaxRetries {
			go eb.retryEvent(ctx, event, subscription)
		} else {
			log.Printf("Max retries exceeded for event %s", event.ID)
			// TODO: Send to dead letter queue
		}
	} else {
		log.Printf("Event %s processed successfully on retry %d", event.ID, event.Retries)
	}
}

// publishToRedis publishes event to Redis
func (eb *EventBus) publishToRedis(event *Event) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal event for Redis: %v", err)
		return
	}

	if err := eb.redis.Publish(eb.ctx, eb.config.RedisChannel, data).Err(); err != nil {
		log.Printf("Failed to publish event to Redis: %v", err)
	}
}

// redisSubscriber subscribes to Redis events
func (eb *EventBus) redisSubscriber() {
	pubsub := eb.redis.Subscribe(eb.ctx, eb.config.RedisChannel)
	defer pubsub.Close()

	ch := pubsub.Channel()

	for {
		select {
		case msg := <-ch:
			var event Event
			if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
				log.Printf("Failed to unmarshal Redis event: %v", err)
				continue
			}

			// Process the event locally
			go eb.processEvent(eb.ctx, &event)

		case <-eb.ctx.Done():
			return
		}
	}
}

// recordEvent records an event in history
func (eb *EventBus) recordEvent(event *Event) {
	eb.historyMu.Lock()
	defer eb.historyMu.Unlock()

	eb.eventHistory = append(eb.eventHistory, event)

	// Trim history if it exceeds max size
	if len(eb.eventHistory) > eb.maxHistorySize {
		eb.eventHistory = eb.eventHistory[1:]
	}
}

// GetEventHistory returns event history
func (eb *EventBus) GetEventHistory(limit int) []*Event {
	eb.historyMu.RLock()
	defer eb.historyMu.RUnlock()

	if limit <= 0 || limit > len(eb.eventHistory) {
		limit = len(eb.eventHistory)
	}

	// Return the most recent events
	start := len(eb.eventHistory) - limit
	if start < 0 {
		start = 0
	}

	history := make([]*Event, limit)
	copy(history, eb.eventHistory[start:])

	return history
}

// GetSubscriptions returns all active subscriptions
func (eb *EventBus) GetSubscriptions() map[string]*Subscription {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	subscriptions := make(map[string]*Subscription)
	for id, subscription := range eb.subscriptions {
		if subscription.Active {
			subscriptions[id] = subscription
		}
	}

	return subscriptions
}

// GetStats returns event bus statistics
func (eb *EventBus) GetStats() *EventStats {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	activeHandlers := 0
	for _, subscription := range eb.subscriptions {
		if subscription.Active {
			activeHandlers++
		}
	}

	return &EventStats{
		// TODO: Implement proper counters
		TotalEvents:     0,
		ProcessedEvents: 0,
		FailedEvents:    0,
		ActiveHandlers:  activeHandlers,
		QueuedEvents:    len(eb.workerPool),
	}
}

// generateEventID generates a unique event ID
func (eb *EventBus) generateEventID() string {
	return fmt.Sprintf("event_%d_%d", time.Now().UnixNano(), eb.getRandomInt())
}

// generateSubscriptionID generates a unique subscription ID
func (eb *EventBus) generateSubscriptionID() string {
	return fmt.Sprintf("sub_%d_%d", time.Now().UnixNano(), eb.getRandomInt())
}

// getRandomInt generates a random integer
func (eb *EventBus) getRandomInt() int {
	// Simple random number generation - use crypto/rand in production
	return int(time.Now().UnixNano() % 1000000)
}

// IsRunning returns whether the event bus is running
func (eb *EventBus) IsRunning() bool {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return eb.running
}

// Shutdown gracefully shuts down the event bus
func (eb *EventBus) Shutdown() error {
	log.Println("Shutting down event bus...")
	eb.cancel()
	eb.running = false
	log.Println("Event bus shutdown complete")
	return nil
}

// Simple event handler implementation
type SimpleEventHandler struct {
	id         string
	eventTypes []EventType
	handlerFunc func(context.Context, *Event) error
}

// NewSimpleEventHandler creates a simple event handler
func NewSimpleEventHandler(id string, eventTypes []EventType, handlerFunc func(context.Context, *Event) error) *SimpleEventHandler {
	return &SimpleEventHandler{
		id:          id,
		eventTypes:  eventTypes,
		handlerFunc: handlerFunc,
	}
}

// HandleEvent implements EventHandler
func (h *SimpleEventHandler) HandleEvent(ctx context.Context, event *Event) error {
	return h.handlerFunc(ctx, event)
}

// GetEventTypes implements EventHandler
func (h *SimpleEventHandler) GetEventTypes() []EventType {
	return h.eventTypes
}

// GetHandlerID implements EventHandler
func (h *SimpleEventHandler) GetHandlerID() string {
	return h.id
}

// Simple event filter implementation
type SimpleEventFilter struct {
	id         string
	filterFunc func(*Event) bool
}

// NewSimpleEventFilter creates a simple event filter
func NewSimpleEventFilter(id string, filterFunc func(*Event) bool) *SimpleEventFilter {
	return &SimpleEventFilter{
		id:         id,
		filterFunc: filterFunc,
	}
}

// ShouldProcess implements EventFilter
func (f *SimpleEventFilter) ShouldProcess(event *Event) bool {
	return f.filterFunc(event)
}

// GetFilterID implements EventFilter
func (f *SimpleEventFilter) GetFilterID() string {
	return f.id
}

// Simple event middleware implementation
type SimpleEventMiddleware struct {
	id            string
	middlewareFunc func(context.Context, *Event, func(context.Context, *Event) error) error
}

// NewSimpleEventMiddleware creates a simple event middleware
func NewSimpleEventMiddleware(id string, middlewareFunc func(context.Context, *Event, func(context.Context, *Event) error) error) *SimpleEventMiddleware {
	return &SimpleEventMiddleware{
		id:             id,
		middlewareFunc: middlewareFunc,
	}
}

// Process implements EventMiddleware
func (m *SimpleEventMiddleware) Process(ctx context.Context, event *Event, next func(context.Context, *Event) error) error {
	return m.middlewareFunc(ctx, event, next)
}

// GetMiddlewareID implements EventMiddleware
func (m *SimpleEventMiddleware) GetMiddlewareID() string {
	return m.id
}

// Helper functions for creating events

// NewEvent creates a new event
func NewEvent(eventType EventType, source string, data map[string]interface{}) *Event {
	return &Event{
		Type:      eventType,
		Source:    source,
		Data:      data,
		Metadata:  make(map[string]interface{}),
		Priority:  EventPriorityNormal,
		Timestamp: time.Now(),
	}
}

// NewScanEvent creates a scan-related event
func NewScanEvent(eventType EventType, scanID, packageName string, data map[string]interface{}) *Event {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["scan_id"] = scanID
	data["package_name"] = packageName

	return NewEvent(eventType, "scanner", data)
}

// NewBatchEvent creates a batch-related event
func NewBatchEvent(eventType EventType, batchID string, data map[string]interface{}) *Event {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["batch_id"] = batchID

	return NewEvent(eventType, "batch_processor", data)
}

// NewSystemEvent creates a system-related event
func NewSystemEvent(eventType EventType, component string, data map[string]interface{}) *Event {
	return NewEvent(eventType, component, data)
}