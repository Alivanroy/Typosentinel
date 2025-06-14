package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
)

type Priority string

const (
	Critical Priority = "critical"
	High     Priority = "high"
	Normal   Priority = "normal"
	Low      Priority = "low"
)

type ScanRequest struct {
	PackageID   string            `json:"package_id"`
	PackageName string            `json:"package_name"`
	Registry    string            `json:"registry"`
	Priority    Priority          `json:"priority"`
	Metadata    map[string]string `json:"metadata"`
	RequestedBy string            `json:"requested_by"`
	Timestamp   time.Time         `json:"timestamp"`
}

type ScannerQueue struct {
	redis   *redis.Client
	workers int
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewScannerQueue(redisClient *redis.Client, workers int) *ScannerQueue {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScannerQueue{
		redis:   redisClient,
		workers: workers,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (sq *ScannerQueue) EnqueueScan(req *ScanRequest) error {
	// Priority queues: critical, high, normal, low
	queueName := fmt.Sprintf("scan_queue:%s", req.Priority)

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	return sq.redis.LPush(sq.ctx, queueName, data).Err()
}

func (sq *ScannerQueue) StartWorkers() {
	for i := 0; i < sq.workers; i++ {
		go sq.worker(i)
	}
}

func (sq *ScannerQueue) worker(id int) {
	queues := []string{"scan_queue:critical", "scan_queue:high", "scan_queue:normal", "scan_queue:low"}

	for {
		select {
		case <-sq.ctx.Done():
			return
		default:
			// BRPOP with timeout for graceful shutdown
			result, err := sq.redis.BRPop(sq.ctx, 5*time.Second, queues...).Result()
			if err == redis.Nil {
				continue
			}
			if err != nil {
				log.Printf("Worker %d: Queue error: %v", id, err)
				continue
			}

			var req ScanRequest
			if err := json.Unmarshal([]byte(result[1]), &req); err != nil {
				log.Printf("Worker %d: Unmarshal error: %v", id, err)
				continue
			}

			sq.processScan(id, &req)
		}
	}
}

func (sq *ScannerQueue) processScan(workerID int, req *ScanRequest) {
	log.Printf("Worker %d: Processing scan for package %s", workerID, req.PackageName)
	// TODO: Integrate with actual scanner implementation
	// This would call the main scanner logic
}

func (sq *ScannerQueue) Stop() {
	sq.cancel()
}