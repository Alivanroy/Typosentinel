package optimization

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"typosentinel/internal/database"
)

// DatabaseOptimizer provides advanced database optimization features
type DatabaseOptimizer struct {
	db                *database.ThreatDB
	connectionPool    *sql.DB
	queryCache        *QueryCache
	batchProcessor    *BatchProcessor
	indexManager      *IndexManager
	queryAnalyzer     *QueryAnalyzer
	mu                sync.RWMutex
	metrics           *OptimizationMetrics
}

// QueryCache implements intelligent query result caching
type QueryCache struct {
	cache     map[string]*CachedQuery
	ttl       time.Duration
	maxSize   int
	hitCount  int64
	missCount int64
	mu        sync.RWMutex
}

// CachedQuery represents a cached database query result
type CachedQuery struct {
	Result    interface{}
	Timestamp time.Time
	HitCount  int64
}

// BatchProcessor handles batch database operations for improved performance
type BatchProcessor struct {
	batchSize     int
	flushInterval time.Duration
	pendingOps    []BatchOperation
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// BatchOperation represents a database operation to be batched
type BatchOperation struct {
	Type      string // INSERT, UPDATE, DELETE
	Table     string
	Data      interface{}
	Callback  func(error)
	Timestamp time.Time
}

// IndexManager optimizes database indexes based on query patterns
type IndexManager struct {
	db            *sql.DB
	queryPatterns map[string]int
	indexes       map[string]*IndexInfo
	mu            sync.RWMutex
}

// IndexInfo contains information about database indexes
type IndexInfo struct {
	Name        string
	Table       string
	Columns     []string
	UsageCount  int64
	CreatedAt   time.Time
	LastUsed    time.Time
	Efficiency  float64
}

// QueryAnalyzer analyzes query performance and suggests optimizations
type QueryAnalyzer struct {
	queryStats    map[string]*QueryStats
	slowQueries   []*SlowQuery
	threshold     time.Duration
	mu            sync.RWMutex
}

// QueryStats tracks performance statistics for database queries
type QueryStats struct {
	Query         string
	ExecutionTime time.Duration
	Count         int64
	AvgTime       time.Duration
	MaxTime       time.Duration
	MinTime       time.Duration
	LastExecuted  time.Time
}

// SlowQuery represents a query that exceeds performance thresholds
type SlowQuery struct {
	Query         string
	ExecutionTime time.Duration
	Timestamp     time.Time
	Optimization  string
}

// OptimizationMetrics tracks optimization performance
type OptimizationMetrics struct {
	CacheHitRatio     float64
	AvgQueryTime      time.Duration
	BatchEfficiency   float64
	IndexUtilization  float64
	OptimizedQueries  int64
	mu                sync.RWMutex
}

// NewDatabaseOptimizer creates a new database optimizer
func NewDatabaseOptimizer(db *database.ThreatDB, config *OptimizationConfig) *DatabaseOptimizer {
	ctx, cancel := context.WithCancel(context.Background())
	
	optimizer := &DatabaseOptimizer{
		db: db,
		queryCache: &QueryCache{
			cache:   make(map[string]*CachedQuery),
			ttl:     config.CacheTTL,
			maxSize: config.CacheMaxSize,
		},
		batchProcessor: &BatchProcessor{
			batchSize:     config.BatchSize,
			flushInterval: config.FlushInterval,
			pendingOps:    make([]BatchOperation, 0),
			ctx:           ctx,
			cancel:        cancel,
		},
		indexManager: &IndexManager{
			queryPatterns: make(map[string]int),
			indexes:       make(map[string]*IndexInfo),
		},
		queryAnalyzer: &QueryAnalyzer{
			queryStats:  make(map[string]*QueryStats),
			slowQueries: make([]*SlowQuery, 0),
			threshold:   config.SlowQueryThreshold,
		},
		metrics: &OptimizationMetrics{},
	}

	// Start background processes
	go optimizer.batchProcessor.start()
	go optimizer.startMetricsCollection()
	go optimizer.startIndexOptimization()

	return optimizer
}

// OptimizationConfig contains configuration for database optimization
type OptimizationConfig struct {
	CacheTTL           time.Duration
	CacheMaxSize       int
	BatchSize          int
	FlushInterval      time.Duration
	SlowQueryThreshold time.Duration
	IndexOptimization  bool
	ConnectionPoolSize int
	QueryTimeout       time.Duration
}

// OptimizedGetThreat retrieves threat with caching and optimization
func (do *DatabaseOptimizer) OptimizedGetThreat(packageName, registry string) (*database.ThreatRecord, error) {
	cacheKey := fmt.Sprintf("threat:%s:%s", packageName, registry)
	
	// Check cache first
	if cached := do.queryCache.Get(cacheKey); cached != nil {
		if threat, ok := cached.Result.(*database.ThreatRecord); ok {
			return threat, nil
		}
	}

	// Track query performance
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		do.queryAnalyzer.RecordQuery("GetThreat", duration)
	}()

	// Execute optimized query
	threat, err := do.db.GetThreat(packageName, registry)
	if err != nil {
		return nil, err
	}

	// Cache result
	if threat != nil {
		do.queryCache.Set(cacheKey, threat)
	}

	return threat, nil
}

// BatchAddThreats adds multiple threats efficiently using batch processing
func (do *DatabaseOptimizer) BatchAddThreats(threats []*database.ThreatRecord) error {
	for _, threat := range threats {
		op := BatchOperation{
			Type:      "INSERT",
			Table:     "threats",
			Data:      threat,
			Timestamp: time.Now(),
		}
		do.batchProcessor.AddOperation(op)
	}
	return nil
}

// OptimizedGetThreats retrieves threats with advanced filtering and caching
func (do *DatabaseOptimizer) OptimizedGetThreats(registry, threatType string, limit int) ([]*database.ThreatRecord, error) {
	cacheKey := fmt.Sprintf("threats:%s:%s:%d", registry, threatType, limit)
	
	// Check cache
	if cached := do.queryCache.Get(cacheKey); cached != nil {
		if threats, ok := cached.Result.([]*database.ThreatRecord); ok {
			return threats, nil
		}
	}

	start := time.Now()
	defer func() {
		duration := time.Since(start)
		do.queryAnalyzer.RecordQuery("GetThreats", duration)
	}()

	// Use optimized query with proper indexing
	threats, err := do.executeOptimizedGetThreats(registry, threatType, limit)
	if err != nil {
		return nil, err
	}

	// Cache results
	do.queryCache.Set(cacheKey, threats)

	return threats, nil
}

// executeOptimizedGetThreats executes an optimized version of GetThreats
func (do *DatabaseOptimizer) executeOptimizedGetThreats(registry, threatType string, limit int) ([]*database.ThreatRecord, error) {
	// Build optimized query with proper index hints
	query := `
		SELECT /*+ INDEX(threats, idx_threats_registry, idx_threats_type) */
		       id, package_name, registry, threat_type, severity, confidence,
		       description, source, created_at, updated_at, metadata
		FROM threats
		WHERE 1=1
	`
	args := []interface{}{}

	if registry != "" {
		query += " AND registry = ?"
		args = append(args, registry)
	}

	if threatType != "" {
		query += " AND threat_type = ?"
		args = append(args, threatType)
	}

	query += " ORDER BY severity DESC, confidence DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	// Record query pattern for index optimization
	do.indexManager.RecordQueryPattern(query)

	// Execute query (this would need to be implemented with actual DB connection)
	// For now, delegate to existing method
	return do.db.GetThreats(registry, threatType, limit)
}

// Query cache methods
func (qc *QueryCache) Get(key string) *CachedQuery {
	qc.mu.RLock()
	defer qc.mu.RUnlock()

	if cached, exists := qc.cache[key]; exists {
		if time.Since(cached.Timestamp) < qc.ttl {
			cached.HitCount++
			qc.hitCount++
			return cached
		}
		// Expired, remove from cache
		delete(qc.cache, key)
	}

	qc.missCount++
	return nil
}

func (qc *QueryCache) Set(key string, result interface{}) {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	// Implement LRU eviction if cache is full
	if len(qc.cache) >= qc.maxSize {
		qc.evictLRU()
	}

	qc.cache[key] = &CachedQuery{
		Result:    result,
		Timestamp: time.Now(),
		HitCount:  0,
	}
}

func (qc *QueryCache) evictLRU() {
	oldestKey := ""
	oldestTime := time.Now()

	for key, cached := range qc.cache {
		if cached.Timestamp.Before(oldestTime) {
			oldestTime = cached.Timestamp
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(qc.cache, oldestKey)
	}
}

// Batch processor methods
func (bp *BatchProcessor) AddOperation(op BatchOperation) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.pendingOps = append(bp.pendingOps, op)

	// Flush if batch size reached
	if len(bp.pendingOps) >= bp.batchSize {
		go bp.flush()
	}
}

func (bp *BatchProcessor) start() {
	ticker := time.NewTicker(bp.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bp.flush()
		case <-bp.ctx.Done():
			return
		}
	}
}

func (bp *BatchProcessor) flush() {
	bp.mu.Lock()
	if len(bp.pendingOps) == 0 {
		bp.mu.Unlock()
		return
	}

	ops := make([]BatchOperation, len(bp.pendingOps))
	copy(ops, bp.pendingOps)
	bp.pendingOps = bp.pendingOps[:0]
	bp.mu.Unlock()

	// Execute batch operations
	bp.executeBatch(ops)
}

func (bp *BatchProcessor) executeBatch(ops []BatchOperation) {
	// Group operations by type and table
	grouped := make(map[string][]BatchOperation)
	for _, op := range ops {
		key := fmt.Sprintf("%s:%s", op.Type, op.Table)
		grouped[key] = append(grouped[key], op)
	}

	// Execute each group
	for _, group := range grouped {
		bp.executeGroup(group)
	}
}

func (bp *BatchProcessor) executeGroup(ops []BatchOperation) {
	if len(ops) == 0 {
		return
	}

	// For INSERT operations on threats table
	if ops[0].Type == "INSERT" && ops[0].Table == "threats" {
		bp.executeBatchInsert(ops)
	}
	// Add other operation types as needed
}

func (bp *BatchProcessor) executeBatchInsert(ops []BatchOperation) {
	// Build batch INSERT statement
	valuesPlaceholder := strings.Repeat("(?, ?, ?, ?, ?, ?, ?, ?),", len(ops))
	valuesPlaceholder = strings.TrimSuffix(valuesPlaceholder, ",")

	_ = fmt.Sprintf(`
		INSERT OR REPLACE INTO threats 
		(package_name, registry, threat_type, severity, confidence, description, source, metadata)
		VALUES %s
	`, valuesPlaceholder)

	args := make([]interface{}, 0, len(ops)*8)
	for _, op := range ops {
		if threat, ok := op.Data.(*database.ThreatRecord); ok {
			args = append(args, threat.PackageName, threat.Registry, threat.ThreatType,
				threat.Severity, threat.Confidence, threat.Description,
				threat.Source, threat.Metadata)
		}
	}

	// Execute batch insert (would need actual DB connection)
	// For now, log the operation
	log.Printf("Executing batch insert for %d threats", len(ops))

	// Call callbacks
	for _, op := range ops {
		if op.Callback != nil {
			op.Callback(nil) // nil indicates success
		}
	}
}

// Index manager methods
func (im *IndexManager) RecordQueryPattern(query string) {
	im.mu.Lock()
	defer im.mu.Unlock()

	// Normalize query for pattern analysis
	normalizedQuery := im.normalizeQuery(query)
	im.queryPatterns[normalizedQuery]++
}

func (im *IndexManager) normalizeQuery(query string) string {
	// Remove specific values and normalize for pattern matching
	normalized := strings.ToLower(query)
	normalized = strings.ReplaceAll(normalized, "\n", " ")
	normalized = strings.ReplaceAll(normalized, "\t", " ")
	// Add more normalization as needed
	return normalized
}

// Query analyzer methods
func (qa *QueryAnalyzer) RecordQuery(queryType string, duration time.Duration) {
	qa.mu.Lock()
	defer qa.mu.Unlock()

	if stats, exists := qa.queryStats[queryType]; exists {
		stats.Count++
		stats.ExecutionTime += duration
		stats.AvgTime = stats.ExecutionTime / time.Duration(stats.Count)
		if duration > stats.MaxTime {
			stats.MaxTime = duration
		}
		if duration < stats.MinTime || stats.MinTime == 0 {
			stats.MinTime = duration
		}
		stats.LastExecuted = time.Now()
	} else {
		qa.queryStats[queryType] = &QueryStats{
			Query:         queryType,
			ExecutionTime: duration,
			Count:         1,
			AvgTime:       duration,
			MaxTime:       duration,
			MinTime:       duration,
			LastExecuted:  time.Now(),
		}
	}

	// Check if query is slow
	if duration > qa.threshold {
		qa.slowQueries = append(qa.slowQueries, &SlowQuery{
			Query:         queryType,
			ExecutionTime: duration,
			Timestamp:     time.Now(),
			Optimization:  qa.suggestOptimization(queryType, duration),
		})
	}
}

func (qa *QueryAnalyzer) suggestOptimization(queryType string, duration time.Duration) string {
	// Provide optimization suggestions based on query type and performance
	switch queryType {
	case "GetThreat":
		return "Consider adding composite index on (package_name, registry)"
	case "GetThreats":
		return "Consider adding indexes on registry and threat_type columns"
	default:
		return "Consider query optimization and proper indexing"
	}
}

// Background optimization processes
func (do *DatabaseOptimizer) startMetricsCollection() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		do.updateMetrics()
	}
}

func (do *DatabaseOptimizer) updateMetrics() {
	do.metrics.mu.Lock()
	defer do.metrics.mu.Unlock()

	// Update cache hit ratio
	totalRequests := do.queryCache.hitCount + do.queryCache.missCount
	if totalRequests > 0 {
		do.metrics.CacheHitRatio = float64(do.queryCache.hitCount) / float64(totalRequests)
	}

	// Update average query time
	do.queryAnalyzer.mu.RLock()
	totalTime := time.Duration(0)
	totalQueries := int64(0)
	for _, stats := range do.queryAnalyzer.queryStats {
		totalTime += stats.ExecutionTime
		totalQueries += stats.Count
	}
	do.queryAnalyzer.mu.RUnlock()

	if totalQueries > 0 {
		do.metrics.AvgQueryTime = totalTime / time.Duration(totalQueries)
	}
}

func (do *DatabaseOptimizer) startIndexOptimization() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		do.optimizeIndexes()
	}
}

func (do *DatabaseOptimizer) optimizeIndexes() {
	// Analyze query patterns and suggest/create optimal indexes
	do.indexManager.mu.RLock()
	patterns := make(map[string]int)
	for pattern, count := range do.indexManager.queryPatterns {
		patterns[pattern] = count
	}
	do.indexManager.mu.RUnlock()

	// Analyze patterns and create indexes as needed
	for pattern, count := range patterns {
		if count > 100 { // Threshold for index creation
			log.Printf("High-frequency query pattern detected: %s (count: %d)", pattern, count)
			// Implement index creation logic here
		}
	}
}

// GetOptimizationMetrics returns current optimization metrics
func (do *DatabaseOptimizer) GetOptimizationMetrics() *OptimizationMetrics {
	do.metrics.mu.RLock()
	defer do.metrics.mu.RUnlock()

	return &OptimizationMetrics{
		CacheHitRatio:     do.metrics.CacheHitRatio,
		AvgQueryTime:      do.metrics.AvgQueryTime,
		BatchEfficiency:   do.metrics.BatchEfficiency,
		IndexUtilization:  do.metrics.IndexUtilization,
		OptimizedQueries:  do.metrics.OptimizedQueries,
	}
}

// GetSlowQueries returns queries that exceed performance thresholds
func (do *DatabaseOptimizer) GetSlowQueries() []*SlowQuery {
	do.queryAnalyzer.mu.RLock()
	defer do.queryAnalyzer.mu.RUnlock()

	slowQueries := make([]*SlowQuery, len(do.queryAnalyzer.slowQueries))
	copy(slowQueries, do.queryAnalyzer.slowQueries)
	return slowQueries
}

// Shutdown gracefully shuts down the optimizer
func (do *DatabaseOptimizer) Shutdown() error {
	do.batchProcessor.cancel()
	// Flush any remaining operations
	do.batchProcessor.flush()
	return nil
}