package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
)

// AddResultHandler adds a result handler to process scan results
func (sq *ScannerQueue) AddResultHandler(handler ResultHandler) {
	sq.mu.Lock()
	defer sq.mu.Unlock()
	sq.resultHandlers = append(sq.resultHandlers, handler)
}

// GetQueueStats returns current queue statistics
func (sq *ScannerQueue) GetQueueStats() (*QueueStats, error) {
	stats := &QueueStats{
		TotalWorkers: sq.workers,
	}

	// Get queue lengths
	queues := []string{"critical", "high", "normal", "low"}
	for _, priority := range queues {
		queueName := fmt.Sprintf("scan_queue:%s", priority)
		count, err := sq.redis.ZCard(sq.ctx, queueName).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to get queue length for %s: %w", priority, err)
		}

		switch priority {
		case "critical":
			stats.CriticalQueue = count
		case "high":
			stats.HighQueue = count
		case "normal":
			stats.NormalQueue = count
		case "low":
			stats.LowQueue = count
		}
	}

	// Get processing count
	processingCount, err := sq.redis.ZCard(sq.ctx, "scan_queue:processing").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get processing queue length: %w", err)
	}
	stats.Processing = processingCount

	// Get dead letter queue count if enabled
	if sq.deadLetterQueue {
		deadLetterCount, err := sq.redis.ZCard(sq.ctx, "scan_queue:dead_letter").Result()
		if err != nil {
			return nil, fmt.Errorf("failed to get dead letter queue length: %w", err)
		}
		stats.DeadLetter = deadLetterCount
	}

	// Calculate active workers (approximate)
	stats.ActiveWorkers = int(processingCount)
	if stats.ActiveWorkers > sq.workers {
		stats.ActiveWorkers = sq.workers
	}

	return stats, nil
}

// DequeueRequest attempts to get a request from the priority queues (public method)
func (sq *ScannerQueue) DequeueRequest(ctx context.Context, timeout time.Duration) (*ScanRequest, error) {
	// Priority order: critical > high > normal > low
	queues := []string{"scan_queue:critical", "scan_queue:high", "scan_queue:normal", "scan_queue:low"}
	return sq.dequeueRequest(queues)
}

// dequeueRequest attempts to get a request from the priority queues
func (sq *ScannerQueue) dequeueRequest(queues []string) (*ScanRequest, error) {
	for _, queueName := range queues {
		// Use ZPOPMIN to get the highest priority (lowest score) item
		result, err := sq.redis.ZPopMin(sq.ctx, queueName, 1).Result()
		if err != nil {
			if err == redis.Nil {
				continue // Try next queue
			}
			return nil, err
		}

		if len(result) == 0 {
			continue // Queue is empty, try next
		}

		// Deserialize the request
		var req ScanRequest
		if err := json.Unmarshal([]byte(result[0].Member.(string)), &req); err != nil {
			log.Printf("Failed to unmarshal scan request: %v", err)
			continue
		}

		// Move to processing queue for visibility timeout
		processingData, _ := json.Marshal(req)
		processingScore := float64(time.Now().Add(sq.visibilityTimeout).Unix())
		sq.redis.ZAdd(sq.ctx, "scan_queue:processing", &redis.Z{
			Score:  processingScore,
			Member: processingData,
		})

		// Update metrics
		priority := string(req.Priority)
		sq.metrics.QueueSize.WithLabelValues(priority).Dec()
		sq.metrics.QueueProcessingTime.WithLabelValues(priority).Observe(time.Since(req.Timestamp).Seconds())

		return &req, nil
	}

	return nil, redis.Nil
}

// retryRequest adds a failed request back to the queue for retry
func (sq *ScannerQueue) retryRequest(req *ScanRequest) {
	req.RetryCount++
	req.Timestamp = time.Now().Add(sq.retryDelay)

	// Reduce priority for retries to avoid blocking new requests
	if req.Priority == PriorityCritical {
		req.Priority = PriorityHigh
	} else if req.Priority == PriorityHigh {
		req.Priority = PriorityNormal
	}

	log.Printf("Retrying scan request %s (attempt %d/%d)", req.ID, req.RetryCount, req.MaxRetries)

	// Re-enqueue with delay
	go func() {
		time.Sleep(sq.retryDelay)
		sq.EnqueueScan(req)
	}()
}

// moveToDeadLetter moves a failed request to the dead letter queue
func (sq *ScannerQueue) moveToDeadLetter(req *ScanRequest, err error) {
	deadLetterData := map[string]interface{}{
		"request":     req,
		"error":       err.Error(),
		"failed_at":   time.Now(),
		"retry_count": req.RetryCount,
	}

	data, _ := json.Marshal(deadLetterData)
	score := float64(time.Now().Unix())

	sq.redis.ZAdd(sq.ctx, "scan_queue:dead_letter", &redis.Z{
		Score:  score,
		Member: data,
	})

	log.Printf("Moved scan request %s to dead letter queue after %d retries", req.ID, req.RetryCount)
}

// removeFromProcessing removes a request from the processing queue
func (sq *ScannerQueue) removeFromProcessing(req *ScanRequest) {
	processingData, _ := json.Marshal(*req)
	sq.redis.ZRem(sq.ctx, "scan_queue:processing", processingData)
}

// handleResult processes the scan result through registered handlers
func (sq *ScannerQueue) handleResult(result *ScanResult) {
	sq.mu.RLock()
	handlers := make([]ResultHandler, len(sq.resultHandlers))
	copy(handlers, sq.resultHandlers)
	sq.mu.RUnlock()

	for _, handler := range handlers {
		if err := handler.HandleResult(result); err != nil {
			log.Printf("Result handler error: %v", err)
		}
	}
}

// calculatePriorityScore calculates the score for priority ordering
func (sq *ScannerQueue) calculatePriorityScore(req *ScanRequest) float64 {
	baseScore := float64(req.Timestamp.Unix())

	// Adjust score based on priority (lower score = higher priority)
	switch req.Priority {
	case PriorityCritical:
		return baseScore - 1000000 // Highest priority
	case PriorityHigh:
		return baseScore - 100000
	case PriorityNormal:
		return baseScore - 10000
	case PriorityLow:
		return baseScore // Lowest priority
	default:
		return baseScore
	}
}

// validateScanRequest validates a scan request
func (sq *ScannerQueue) validateScanRequest(req *ScanRequest) error {
	if req.PackageName == "" {
		return fmt.Errorf("package name is required")
	}

	if req.Registry == "" {
		return fmt.Errorf("registry is required")
	}

	if req.OrganizationID == "" {
		return fmt.Errorf("organization ID is required")
	}

	if req.Priority == "" {
		req.Priority = PriorityNormal
	}

	// Validate priority
	validPriorities := map[Priority]bool{
		PriorityCritical: true,
		PriorityHigh:     true,
		PriorityNormal:   true,
		PriorityLow:      true,
	}

	if !validPriorities[req.Priority] {
		return fmt.Errorf("invalid priority: %s", req.Priority)
	}

	return nil
}

// CleanupExpiredProcessing removes expired items from the processing queue
func (sq *ScannerQueue) CleanupExpiredProcessing() error {
	now := float64(time.Now().Unix())

	// Remove expired items from processing queue
	expiredItems, err := sq.redis.ZRangeByScore(sq.ctx, "scan_queue:processing", &redis.ZRangeBy{
		Min: "0",
		Max: fmt.Sprintf("%f", now),
	}).Result()

	if err != nil {
		return fmt.Errorf("failed to get expired processing items: %w", err)
	}

	for _, item := range expiredItems {
		var req ScanRequest
		if err := json.Unmarshal([]byte(item), &req); err != nil {
			continue
		}

		// Re-enqueue expired requests
		log.Printf("Re-enqueueing expired processing request %s", req.ID)
		sq.EnqueueScan(&req)

		// Remove from processing queue
		sq.redis.ZRem(sq.ctx, "scan_queue:processing", item)
	}

	return nil
}

// StartCleanupWorker starts a background worker to clean up expired processing items
func (sq *ScannerQueue) StartCleanupWorker() {
	go func() {
		ticker := time.NewTicker(sq.visibilityTimeout / 2)
		defer ticker.Stop()

		for {
			select {
			case <-sq.ctx.Done():
				return
			case <-ticker.C:
				if err := sq.CleanupExpiredProcessing(); err != nil {
					log.Printf("Cleanup worker error: %v", err)
				}
			}
		}
	}()
}