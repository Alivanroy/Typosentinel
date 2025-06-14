package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

type EventType string

const (
	PackageScanned  EventType = "package.scanned"
	ThreatDetected  EventType = "threat.detected"
	BatchCompleted  EventType = "batch.completed"
	PolicyViolation EventType = "policy.violation"
)

type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

type EventHandler func(*Event) error

type EventBus struct {
	redis    *redis.Client
	handlers map[EventType][]EventHandler
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewEventBus(redis *redis.Client) *EventBus {
	ctx, cancel := context.WithCancel(context.Background())
	return &EventBus{
		redis:    redis,
		handlers: make(map[EventType][]EventHandler),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (eb *EventBus) Publish(event *Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Publish to Redis streams for persistence and replay
	err = eb.redis.XAdd(eb.ctx, &redis.XAddArgs{
		Stream: fmt.Sprintf("events:%s", event.Type),
		Values: map[string]interface{}{
			"data": string(data),
		},
	}).Err()

	if err != nil {
		return err
	}

	// Also publish to pub/sub for real-time notifications
	return eb.redis.Publish(eb.ctx, fmt.Sprintf("events:%s", event.Type), data).Err()
}

func (eb *EventBus) Subscribe(eventType EventType, handler EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.handlers[eventType] == nil {
		eb.handlers[eventType] = make([]EventHandler, 0)
	}
	eb.handlers[eventType] = append(eb.handlers[eventType], handler)
}

func (eb *EventBus) StartListening() {
	// Start Redis pub/sub listener
	go eb.listenPubSub()

	// Start stream consumers for each event type
	for eventType := range eb.handlers {
		go eb.consumeStream(eventType)
	}
}

func (eb *EventBus) listenPubSub() {
	// Subscribe to all event channels
	pattern := "events:*"
	pubsub := eb.redis.PSubscribe(eb.ctx, pattern)
	defer pubsub.Close()

	ch := pubsub.Channel()
	for {
		select {
		case <-eb.ctx.Done():
			return
		case msg := <-ch:
			var event Event
			if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
				continue
			}

			// Handle event with registered handlers
			eb.handleEvent(&event)
		}
	}
}

func (eb *EventBus) consumeStream(eventType EventType) {
	streamName := fmt.Sprintf("events:%s", eventType)
	consumerGroup := "typosentinel-processors"
	consumerName := fmt.Sprintf("consumer-%s", eventType)

	// Create consumer group if it doesn't exist
	eb.redis.XGroupCreate(eb.ctx, streamName, consumerGroup, "0", &redis.XGroupCreateArgs{
		MkStream: true,
	})

	for {
		select {
		case <-eb.ctx.Done():
			return
		default:
			// Read from stream
			streams, err := eb.redis.XReadGroup(eb.ctx, &redis.XReadGroupArgs{
				Group:    consumerGroup,
				Consumer: consumerName,
				Streams:  []string{streamName, ">"},
				Count:    1,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				continue
			}

			for _, stream := range streams {
				for _, message := range stream.Messages {
					var event Event
					if err := json.Unmarshal([]byte(message.Values["data"].(string)), &event); err != nil {
						continue
					}

					// Process event
					if eb.handleEvent(&event) == nil {
						// Acknowledge message on successful processing
						eb.redis.XAck(eb.ctx, streamName, consumerGroup, message.ID)
					}
				}
			}
		}
	}
}

func (eb *EventBus) handleEvent(event *Event) error {
	eb.mu.RLock()
	handlers := eb.handlers[event.Type]
	eb.mu.RUnlock()

	for _, handler := range handlers {
		if err := handler(event); err != nil {
			// Log error but continue with other handlers
			fmt.Printf("Event handler error: %v\n", err)
			return err
		}
	}

	return nil
}

func (eb *EventBus) Stop() {
	eb.cancel()
}

// Event builders for common events
func NewPackageScannedEvent(packageName, registry string, riskScore float64) *Event {
	return &Event{
		ID:   fmt.Sprintf("scan-%d", time.Now().UnixNano()),
		Type: PackageScanned,
		Source: "scanner",
		Data: map[string]interface{}{
			"package_name": packageName,
			"registry":     registry,
			"risk_score":   riskScore,
		},
		Timestamp: time.Now(),
	}
}

func NewThreatDetectedEvent(packageName string, threatType string, severity string) *Event {
	return &Event{
		ID:   fmt.Sprintf("threat-%d", time.Now().UnixNano()),
		Type: ThreatDetected,
		Source: "detector",
		Data: map[string]interface{}{
			"package_name": packageName,
			"threat_type":  threatType,
			"severity":     severity,
		},
		Timestamp: time.Now(),
	}
}

func NewBatchCompletedEvent(batchID string, totalPackages, successCount, failureCount int) *Event {
	return &Event{
		ID:   fmt.Sprintf("batch-%s", batchID),
		Type: BatchCompleted,
		Source: "batch_processor",
		Data: map[string]interface{}{
			"batch_id":       batchID,
			"total_packages": totalPackages,
			"success_count":  successCount,
			"failure_count":  failureCount,
		},
		Timestamp: time.Now(),
	}
}