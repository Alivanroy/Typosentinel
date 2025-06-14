package batch

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/typosentinel/typosentinel/internal/database"
	"github.com/typosentinel/typosentinel/internal/scanner"
	"github.com/typosentinel/typosentinel/pkg/types"
)

type BatchProcessor struct {
	scanner     *scanner.Scanner
	db          *database.DB
	concurrency int
}

func NewBatchProcessor(scanner *scanner.Scanner, db *database.DB, concurrency int) *BatchProcessor {
	return &BatchProcessor{
		scanner:     scanner,
		db:          db,
		concurrency: concurrency,
	}
}

func (bp *BatchProcessor) ProcessPackageList(packages []string, orgID string) error {
	// Create batch job record
	batch := &types.BatchJob{
		ID:              uuid.New().String(),
		OrganizationID:  orgID,
		TotalPackages:   len(packages),
		Status:          "running",
		CreatedAt:       time.Now(),
		ProcessedCount:  0,
		SuccessCount:    0,
		FailureCount:    0,
	}

	if err := bp.db.CreateBatchJob(batch); err != nil {
		return err
	}

	// Process in chunks with rate limiting
	sem := make(chan struct{}, bp.concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, pkg := range packages {
		wg.Add(1)
		go func(packageName string, index int) {
			defer wg.Done()
			sem <- struct{}{} // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			result, err := bp.scanner.Scan(context.Background(), &types.Package{
				Name: packageName,
			})

			// Update batch progress
			mu.Lock()
			bp.updateBatchProgress(batch.ID, index+1, result, err)
			mu.Unlock()
		}(pkg, i)
	}

	wg.Wait()
	bp.finalizeBatch(batch.ID)
	return nil
}

func (bp *BatchProcessor) updateBatchProgress(batchID string, processed int, result *types.ScanResult, err error) {
	// Update batch job progress in database
	update := map[string]interface{}{
		"processed_count": processed,
		"updated_at":      time.Now(),
	}

	if err != nil {
		update["failure_count"] = "failure_count + 1"
	} else {
		update["success_count"] = "success_count + 1"
	}

	bp.db.UpdateBatchJob(batchID, update)
}

func (bp *BatchProcessor) finalizeBatch(batchID string) {
	// Mark batch as completed
	update := map[string]interface{}{
		"status":      "completed",
		"completed_at": time.Now(),
	}

	bp.db.UpdateBatchJob(batchID, update)
}

func (bp *BatchProcessor) GetBatchStatus(batchID string) (*types.BatchJob, error) {
	return bp.db.GetBatchJob(batchID)
}

func (bp *BatchProcessor) ListBatches(orgID string, limit, offset int) ([]*types.BatchJob, error) {
	return bp.db.ListBatchJobs(orgID, limit, offset)
}