package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// InMemoryScanQueue implements the ScanQueue interface using in-memory storage
type InMemoryScanQueue struct {
	mu         sync.RWMutex
	pending    []*repository.ScanRequest
	inProgress map[string]*repository.ScanRequest
	completed  map[string]*repository.ScanRequest
	failed     map[string]*repository.ScanRequest
}

// NewInMemoryScanQueue creates a new in-memory scan queue
func NewInMemoryScanQueue() *InMemoryScanQueue {
	return &InMemoryScanQueue{
		pending:    make([]*repository.ScanRequest, 0),
		inProgress: make(map[string]*repository.ScanRequest),
		completed:  make(map[string]*repository.ScanRequest),
		failed:     make(map[string]*repository.ScanRequest),
	}
}

// Enqueue adds a scan request to the queue
func (q *InMemoryScanQueue) Enqueue(ctx context.Context, request *repository.ScanRequest) error {
	if request == nil {
		return fmt.Errorf("scan request cannot be nil")
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// Set creation time if not set
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}

	q.pending = append(q.pending, request)
	return nil
}

// Dequeue retrieves the next scan request from the queue
func (q *InMemoryScanQueue) Dequeue(ctx context.Context) (*repository.ScanRequest, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.pending) == 0 {
		return nil, nil // No pending requests
	}

	// Get the first request
	request := q.pending[0]
	q.pending = q.pending[1:]

	// Move to in-progress
	q.inProgress[request.ScanID] = request

	return request, nil
}

// Size returns the number of pending requests
func (q *InMemoryScanQueue) Size(ctx context.Context) (int, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	return len(q.pending), nil
}

// Clear removes all requests from the queue
func (q *InMemoryScanQueue) Clear(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.pending = make([]*repository.ScanRequest, 0)
	q.inProgress = make(map[string]*repository.ScanRequest)
	q.completed = make(map[string]*repository.ScanRequest)
	q.failed = make(map[string]*repository.ScanRequest)

	return nil
}

// GetPending returns all pending scan requests
func (q *InMemoryScanQueue) GetPending(ctx context.Context) ([]*repository.ScanRequest, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	// Return a copy to avoid race conditions
	pending := make([]*repository.ScanRequest, len(q.pending))
	copy(pending, q.pending)

	return pending, nil
}

// GetInProgress returns all in-progress scan requests
func (q *InMemoryScanQueue) GetInProgress(ctx context.Context) ([]*repository.ScanRequest, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	inProgress := make([]*repository.ScanRequest, 0, len(q.inProgress))
	for _, request := range q.inProgress {
		inProgress = append(inProgress, request)
	}

	return inProgress, nil
}

// MarkCompleted marks a scan request as completed
func (q *InMemoryScanQueue) MarkCompleted(ctx context.Context, scanID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	request, exists := q.inProgress[scanID]
	if !exists {
		return fmt.Errorf("scan request with ID %s not found in progress", scanID)
	}

	delete(q.inProgress, scanID)
	q.completed[scanID] = request

	return nil
}

// MarkFailed marks a scan request as failed
func (q *InMemoryScanQueue) MarkFailed(ctx context.Context, scanID string, err error) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	request, exists := q.inProgress[scanID]
	if !exists {
		return fmt.Errorf("scan request with ID %s not found in progress", scanID)
	}

	delete(q.inProgress, scanID)
	q.failed[scanID] = request

	return nil
}
