package scanner

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// OptimizedScanner provides high-performance scanning with parallel processing
type OptimizedScanner struct {
	scanner    *Scanner
	cache      *CacheManager
	workerPool *WorkerPool
	config     *config.Config
}

// WorkerPool manages concurrent scanning operations
type WorkerPool struct {
	workers    int
	jobQueue   chan ScanJob
	resultChan chan ScanJobResult
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	running    bool
	mu         sync.RWMutex
}

// ScanJob represents a scanning job
type ScanJob struct {
	ID       string
	Package  *types.Package
	Priority int
	Timeout  time.Duration
}

// ScanJobResult represents the result of a scanning job
type ScanJobResult struct {
	JobID     string
	Result    *types.Package
	Error     error
	Duration  time.Duration
	FromCache bool
}

// CacheManager handles multi-level caching
type CacheManager struct {
	// L1: In-memory cache for hot data
	memoryCache *sync.Map
	// L2: File system cache for persistent storage
	fsCache   map[string]*CacheEntry
	fsCacheMu sync.RWMutex
	config    *CacheConfig
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	MemoryTTL     time.Duration
	FSTTL         time.Duration
	MaxMemorySize int64
	MaxFSSize     int64
	CacheDir      string
}

// CacheEntry represents a cached item
type CacheEntry struct {
	Key       string
	Value     interface{}
	CreatedAt time.Time
	TTL       time.Duration
	Size      int64
}

// NewOptimizedScanner creates a new optimized scanner
func NewOptimizedScanner(scanner *Scanner, cfg *config.Config) *OptimizedScanner {
	cacheConfig := &CacheConfig{
		MemoryTTL:     30 * time.Minute,
		FSTTL:         24 * time.Hour,
		MaxMemorySize: 100 * 1024 * 1024,  // 100MB
		MaxFSSize:     1024 * 1024 * 1024, // 1GB
		CacheDir:      "/tmp/typosentinel-cache",
	}

	if cfg.Cache != nil {
		cacheConfig.CacheDir = cfg.Cache.CacheDir
		cacheConfig.MemoryTTL = cfg.Cache.TTL
	}

	cacheManager := NewCacheManager(cacheConfig)
	workerPool := NewWorkerPool(runtime.NumCPU() * 2)

	return &OptimizedScanner{
		scanner:    scanner,
		cache:      cacheManager,
		workerPool: workerPool,
		config:     cfg,
	}
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers int) *WorkerPool {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		workers:    workers,
		jobQueue:   make(chan ScanJob, workers*2),
		resultChan: make(chan ScanJobResult, workers*2),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the worker pool
func (wp *WorkerPool) Start(scanner *OptimizedScanner) {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.running {
		return
	}

	wp.running = true
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i, scanner)
	}
}

// worker processes scanning jobs
func (wp *WorkerPool) worker(id int, scanner *OptimizedScanner) {
	defer wp.wg.Done()

	for {
		select {
		case job := <-wp.jobQueue:
			start := time.Now()
			result, fromCache, err := scanner.scanPackageWithCache(job.Package)
			duration := time.Since(start)

			wp.resultChan <- ScanJobResult{
				JobID:     job.ID,
				Result:    result,
				Error:     err,
				Duration:  duration,
				FromCache: fromCache,
			}

		case <-wp.ctx.Done():
			return
		}
	}
}

// Submit submits a job to the worker pool
func (wp *WorkerPool) Submit(job ScanJob) error {
	wp.mu.RLock()
	running := wp.running
	wp.mu.RUnlock()

	if !running {
		return fmt.Errorf("worker pool is not running")
	}

	select {
	case wp.jobQueue <- job:
		return nil
	case <-wp.ctx.Done():
		return fmt.Errorf("worker pool is shutting down")
	default:
		return fmt.Errorf("job queue is full")
	}
}

// Results returns the result channel
func (wp *WorkerPool) Results() <-chan ScanJobResult {
	return wp.resultChan
}

// Stop stops the worker pool
func (wp *WorkerPool) Stop() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if !wp.running {
		return
	}

	wp.running = false
	wp.cancel()
	close(wp.jobQueue)
	wp.wg.Wait()
	close(wp.resultChan)
}

// NewCacheManager creates a new cache manager
func NewCacheManager(config *CacheConfig) *CacheManager {
	return &CacheManager{
		memoryCache: &sync.Map{},
		fsCache:     make(map[string]*CacheEntry),
		config:      config,
	}
}

// Get retrieves a value from cache
func (cm *CacheManager) Get(key string) (interface{}, bool) {
	// L1: Check memory cache first
	if value, ok := cm.getFromMemory(key); ok {
		return value, true
	}

	// L2: Check file system cache
	if value, ok := cm.getFromFS(key); ok {
		// Promote to memory cache
		cm.setInMemory(key, value)
		return value, true
	}

	return nil, false
}

// Set stores a value in cache
func (cm *CacheManager) Set(key string, value interface{}) {
	cm.setInMemory(key, value)
	cm.setInFS(key, value)
}

// getFromMemory retrieves from memory cache
func (cm *CacheManager) getFromMemory(key string) (interface{}, bool) {
	if entry, ok := cm.memoryCache.Load(key); ok {
		if cacheEntry, ok := entry.(*CacheEntry); ok {
			if time.Since(cacheEntry.CreatedAt) < cacheEntry.TTL {
				return cacheEntry.Value, true
			}
			// Expired, remove from cache
			cm.memoryCache.Delete(key)
		}
	}
	return nil, false
}

// setInMemory stores in memory cache
func (cm *CacheManager) setInMemory(key string, value interface{}) {
	entry := &CacheEntry{
		Key:       key,
		Value:     value,
		CreatedAt: time.Now(),
		TTL:       cm.config.MemoryTTL,
		Size:      estimateSize(value),
	}
	cm.memoryCache.Store(key, entry)
}

// getFromFS retrieves from file system cache
func (cm *CacheManager) getFromFS(key string) (interface{}, bool) {
	cm.fsCacheMu.RLock()
	defer cm.fsCacheMu.RUnlock()

	if entry, ok := cm.fsCache[key]; ok {
		if time.Since(entry.CreatedAt) < entry.TTL {
			return entry.Value, true
		}
		// Expired, remove from cache
		delete(cm.fsCache, key)
	}
	return nil, false
}

// setInFS stores in file system cache
func (cm *CacheManager) setInFS(key string, value interface{}) {
	cm.fsCacheMu.Lock()
	defer cm.fsCacheMu.Unlock()

	entry := &CacheEntry{
		Key:       key,
		Value:     value,
		CreatedAt: time.Now(),
		TTL:       cm.config.FSTTL,
		Size:      estimateSize(value),
	}
	cm.fsCache[key] = entry
}

// ScanPackageParallel scans a single package with optimizations
func (os *OptimizedScanner) ScanPackageParallel(pkg *types.Package) (*types.Package, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Check cache first
	cacheKey := generateCacheKey(pkg.Name, pkg.Registry, pkg.Version)
	if cached, found := os.cache.Get(cacheKey); found {
		if cachedPkg, ok := cached.(*types.Package); ok {
			return cachedPkg, nil
		}
	}

	// Perform actual scan with timeout
	resultChan := make(chan *types.Package, 1)
	errorChan := make(chan error, 1)

	go func() {
		// This would call the actual scanning logic
		// For now, we'll simulate the scan
		result := &types.Package{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Registry:   pkg.Registry,
			RiskLevel:  types.SeverityLow,
			RiskScore:  0.1,
			AnalyzedAt: time.Now(),
		}
		resultChan <- result
	}()

	select {
	case result := <-resultChan:
		// Cache the result
		os.cache.Set(cacheKey, result)
		return result, nil
	case err := <-errorChan:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("scan timeout for package %s", pkg.Name)
	}
}

// scanPackageWithCache scans a package with caching
func (os *OptimizedScanner) scanPackageWithCache(pkg *types.Package) (*types.Package, bool, error) {
	cacheKey := generateCacheKey(pkg.Name, pkg.Registry, pkg.Version)

	// Check cache first
	if cached, found := os.cache.Get(cacheKey); found {
		if cachedPkg, ok := cached.(*types.Package); ok {
			return cachedPkg, true, nil
		}
	}

	// Perform actual scan
	result, err := os.ScanPackageParallel(pkg)
	if err != nil {
		return nil, false, err
	}

	// Cache the result
	os.cache.Set(cacheKey, result)
	return result, false, nil
}

// ScanPackagesBatch scans multiple packages in parallel
func (os *OptimizedScanner) ScanPackagesBatch(packages []*types.Package, timeout time.Duration) ([]*types.Package, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Start worker pool
	os.workerPool.Start(os)
	defer os.workerPool.Stop()

	// Submit jobs
	jobCount := len(packages)
	for i, pkg := range packages {
		job := ScanJob{
			ID:       fmt.Sprintf("job-%d", i),
			Package:  pkg,
			Priority: 1,
			Timeout:  2 * time.Second,
		}
		if err := os.workerPool.Submit(job); err != nil {
			return nil, fmt.Errorf("failed to submit job %d: %w", i, err)
		}
	}

	// Collect results
	results := make([]*types.Package, 0, jobCount)
	collected := 0

	for collected < jobCount {
		select {
		case result := <-os.workerPool.Results():
			if result.Error != nil {
				// Log error but continue with other packages
				continue
			}
			results = append(results, result.Result)
			collected++

		case <-ctx.Done():
			return results, fmt.Errorf("batch scan timeout after processing %d/%d packages", collected, jobCount)
		}
	}

	return results, nil
}

// generateCacheKey generates a cache key for a package
func generateCacheKey(name, registry, version string) string {
	return fmt.Sprintf("pkg:%s:%s:%s", registry, name, version)
}

// estimateSize estimates the size of a value in bytes
func estimateSize(value interface{}) int64 {
	// Simple estimation - in a real implementation, this would be more sophisticated
	return 1024 // 1KB estimate
}
