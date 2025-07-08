package events

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/events"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// EventBus manages event publishing and subscription
type EventBus struct {
	logger      logger.Logger
	subscribers map[events.EventType][]events.EventSubscriber
	filters     map[string]*events.EventFilter
	eventQueue  chan *events.SecurityEvent
	mu          sync.RWMutex
	running     bool
	metrics     *BusMetrics
}

// BusMetrics tracks event bus performance metrics
type BusMetrics struct {
	EventsPublished   int64
	EventsDelivered   int64
	EventsDropped     int64
	SubscriberErrors  int64
	AverageLatency    time.Duration
	mu                sync.RWMutex
}

// NewEventBus creates a new event bus instance
func NewEventBus(logger logger.Logger, queueSize int) *EventBus {
	return &EventBus{
		logger:      logger,
		subscribers: make(map[events.EventType][]events.EventSubscriber),
		filters:     make(map[string]*events.EventFilter),
		eventQueue:  make(chan *events.SecurityEvent, queueSize),
		metrics:     &BusMetrics{},
	}
}

// Subscribe adds a subscriber for specific event types
func (eb *EventBus) Subscribe(eventType events.EventType, subscriber events.EventSubscriber) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.subscribers[eventType] = append(eb.subscribers[eventType], subscriber)

	eb.logger.Info("Event subscriber registered", map[string]interface{}{
		"subscriber_id": subscriber.GetID(),
		"event_type":    string(eventType),
	})
}

// Unsubscribe removes a subscriber
func (eb *EventBus) Unsubscribe(eventType events.EventType, subscriberID string) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	subscribers := eb.subscribers[eventType]
	for i, subscriber := range subscribers {
		if subscriber.GetID() == subscriberID {
			// Remove subscriber from slice
			eb.subscribers[eventType] = append(subscribers[:i], subscribers[i+1:]...)
			break
		}
	}

	eb.logger.Info("Event subscriber unregistered", map[string]interface{}{
		"subscriber_id": subscriberID,
		"event_type":    string(eventType),
	})
}

// SetFilter sets a filter for a specific subscriber
func (eb *EventBus) SetFilter(subscriberID string, filter *events.EventFilter) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.filters[subscriberID] = filter

	eb.logger.Debug("Event filter set", map[string]interface{}{
		"subscriber_id": subscriberID,
		"filter":        filter,
	})
}

// Publish publishes an event to the event bus
func (eb *EventBus) Publish(ctx context.Context, event *events.SecurityEvent) error {
	start := time.Now()

	select {
	case eb.eventQueue <- event:
		eb.updateMetrics(func(m *BusMetrics) {
			m.EventsPublished++
			m.AverageLatency = time.Since(start)
		})

		eb.logger.Debug("Event published", map[string]interface{}{
			"event_id":   event.ID,
			"event_type": string(event.Type),
			"severity":   string(event.Severity),
		})

		return nil

	case <-ctx.Done():
		return ctx.Err()

	default:
		eb.updateMetrics(func(m *BusMetrics) {
			m.EventsDropped++
		})

		return fmt.Errorf("event queue is full, dropping event %s", event.ID)
	}
}

// Start starts the event bus processing loop
func (eb *EventBus) Start(ctx context.Context) {
	eb.mu.Lock()
	if eb.running {
		eb.mu.Unlock()
		return
	}
	eb.running = true
	eb.mu.Unlock()

	eb.logger.Info("Event bus started", nil)

	for {
		select {
		case event := <-eb.eventQueue:
			eb.processEvent(ctx, event)

		case <-ctx.Done():
			eb.mu.Lock()
			eb.running = false
			eb.mu.Unlock()
			eb.logger.Info("Event bus stopped", nil)
			return
		}
	}
}

// processEvent processes a single event and delivers it to subscribers
func (eb *EventBus) processEvent(ctx context.Context, event *events.SecurityEvent) {
	eb.mu.RLock()
	subscribers := eb.subscribers[event.Type]
	eb.mu.RUnlock()

	if len(subscribers) == 0 {
		eb.logger.Debug("No subscribers for event type", map[string]interface{}{
			"event_type": string(event.Type),
			"event_id":   event.ID,
		})
		return
	}

	// Process subscribers concurrently
	var wg sync.WaitGroup
	for _, subscriber := range subscribers {
		wg.Add(1)
		go func(sub events.EventSubscriber) {
			defer wg.Done()
			eb.deliverToSubscriber(ctx, event, sub)
		}(subscriber)
	}

	wg.Wait()
}

// deliverToSubscriber delivers an event to a specific subscriber
func (eb *EventBus) deliverToSubscriber(ctx context.Context, event *events.SecurityEvent, subscriber events.EventSubscriber) {
	start := time.Now()
	subscriberID := subscriber.GetID()

	// Check if event matches subscriber's filter
	eb.mu.RLock()
	filter := eb.filters[subscriberID]
	eb.mu.RUnlock()

	if filter != nil && !event.MatchesFilter(filter) {
		eb.logger.Debug("Event filtered out for subscriber", map[string]interface{}{
			"subscriber_id": subscriberID,
			"event_id":      event.ID,
		})
		return
	}

	// Deliver event with timeout
	deliveryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := subscriber.Handle(deliveryCtx, event); err != nil {
		eb.updateMetrics(func(m *BusMetrics) {
			m.SubscriberErrors++
		})

		eb.logger.Error("Subscriber failed to handle event", map[string]interface{}{
			"subscriber_id": subscriberID,
			"event_id":      event.ID,
			"error":         err,
			"latency_ms":    time.Since(start).Milliseconds(),
		})
		return
	}

	eb.updateMetrics(func(m *BusMetrics) {
		m.EventsDelivered++
	})

	eb.logger.Debug("Event delivered to subscriber", map[string]interface{}{
		"subscriber_id": subscriberID,
		"event_id":      event.ID,
		"latency_ms":    time.Since(start).Milliseconds(),
	})
}

// GetMetrics returns current event bus metrics
func (eb *EventBus) GetMetrics() BusMetrics {
	eb.metrics.mu.RLock()
	defer eb.metrics.mu.RUnlock()

	return *eb.metrics
}

// updateMetrics safely updates metrics
func (eb *EventBus) updateMetrics(updateFn func(*BusMetrics)) {
	eb.metrics.mu.Lock()
	defer eb.metrics.mu.Unlock()
	updateFn(eb.metrics)
}

// IsRunning returns whether the event bus is currently running
func (eb *EventBus) IsRunning() bool {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return eb.running
}

// GetSubscriberCount returns the number of subscribers for an event type
func (eb *EventBus) GetSubscriberCount(eventType events.EventType) int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.subscribers[eventType])
}

// Stop gracefully stops the event bus
func (eb *EventBus) Stop() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.running {
		close(eb.eventQueue)
		eb.running = false
		eb.logger.Info("Event bus stop requested", nil)
	}
}