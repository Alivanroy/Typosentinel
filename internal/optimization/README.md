# Typosentinel Optimization System

A comprehensive production optimization system for Typosentinel that provides database query optimization, multi-level caching strategies, and performance monitoring.

## Overview

The optimization system consists of several key components:

- **Database Optimizer**: Query caching, batch processing, and index management
- **Cache Manager**: Multi-level caching (L1: in-memory, L2: file-based, L3: Redis)
- **Performance Optimizer**: Resource monitoring, concurrency management, and optimization engine
- **Integration Manager**: Unified interface for all optimization features

## Features

### Database Optimization
- Query result caching with configurable TTL
- Batch processing for improved throughput
- Automatic index management and optimization
- Query performance analysis and slow query detection
- Connection pooling and timeout management

### Multi-Level Caching
- **L1 Cache (In-Memory)**: Fast access with LRU/LFU eviction policies
- **L2 Cache (File-Based)**: Persistent caching with compression
- **L3 Cache (Redis)**: Distributed caching for scalability
- Cache warming and preloading strategies
- Intelligent cache invalidation and refresh

### Performance Monitoring
- Real-time resource usage monitoring (CPU, memory, goroutines)
- Performance profiling and bottleneck detection
- Adaptive optimization based on workload patterns
- Comprehensive metrics collection and reporting
- Alert system for performance degradation

### Optimization Engine
- Machine learning-based optimization suggestions
- Automatic parameter tuning based on usage patterns
- Performance regression detection
- Workload-specific configuration recommendations

## Quick Start

### Basic Usage

```go
package main

import (
    "log"
    "typosentinel/internal/database"
    "typosentinel/internal/optimization"
)

func main() {
    // Initialize database
    db, err := database.NewThreatDB("threats.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Create optimization manager with production settings
    optManager, err := optimization.QuickOptimizationSetup(db)
    if err != nil {
        log.Fatal(err)
    }

    // Start optimization
    if err := optManager.Start(); err != nil {
        log.Fatal(err)
    }
    defer optManager.Stop()

    // Perform optimized threat lookup
    threat, err := optManager.OptimizedThreatLookup("package-name", "npm")
    if err != nil {
        log.Printf("Lookup error: %v", err)
    }

    // Get optimization statistics
    stats := optManager.GetOptimizationStats()
    log.Printf("Cache hit ratio: %.2f%%", stats.Cache.OverallHitRatio*100)
}
```

### Batch Processing

```go
// Prepare batch of packages
packages := []types.Package{
    {Name: "express", Version: "4.18.0", Registry: "npm"},
    {Name: "lodash", Version: "4.17.21", Registry: "npm"},
    {Name: "react", Version: "18.2.0", Registry: "npm"},
}

// Perform batch optimized lookup
threats, err := optManager.BatchOptimizedThreatLookup(packages)
if err != nil {
    log.Printf("Batch lookup error: %v", err)
}

log.Printf("Checked %d packages, found %d threats", len(packages), len(threats))
```

### Custom Configuration

```go
// Create custom configuration
config := &optimization.PerformanceConfig{
    Database: optimization.DatabaseConfig{
        QueryCacheSize:    1000,
        BatchSize:         100,
        ConnectionTimeout: 30 * time.Second,
        QueryTimeout:      10 * time.Second,
        MaxConnections:    20,
        EnableQueryCache:  true,
        EnableBatching:    true,
    },
    Cache: optimization.CacheConfig{
        L1: optimization.L1CacheConfig{
            Enabled:        true,
            MaxSize:        10000,
            TTL:            5 * time.Minute,
            EvictionPolicy: "lru",
        },
        L2: optimization.L2CacheConfig{
            Enabled:     true,
            MaxSizeMB:   100,
            TTL:         30 * time.Minute,
            Compression: true,
        },
        L3: optimization.L3CacheConfig{
            Enabled:   true,
            RedisURL:  "redis://localhost:6379",
            TTL:       2 * time.Hour,
            KeyPrefix: "typosentinel:",
        },
    },
    // ... other configuration options
}

// Create optimization manager with custom config
optManager := &optimization.OptimizationManager{
    // Initialize with custom config
}
```

## Configuration

### Environment-Based Configuration

The system supports different configuration profiles:

- **Production**: Optimized for high throughput and reliability
- **Development**: Balanced performance with debugging capabilities
- **Testing**: Minimal resource usage for testing environments

```go
// Load configuration based on environment
config := optimization.ConfigFromEnvironment("production")

// Get system-optimized configuration
recommendedConfig := optimization.GetRecommendedConfig()

// Validate configuration
if err := optimization.ValidateConfig(config); err != nil {
    log.Fatal("Invalid configuration:", err)
}
```

### Configuration Options

#### Database Configuration
- `QueryCacheSize`: Number of queries to cache
- `BatchSize`: Number of operations per batch
- `ConnectionTimeout`: Database connection timeout
- `QueryTimeout`: Individual query timeout
- `MaxConnections`: Maximum database connections
- `EnableQueryCache`: Enable/disable query caching
- `EnableBatching`: Enable/disable batch processing

#### Cache Configuration
- **L1 Cache**: In-memory cache settings
  - `MaxSize`: Maximum number of entries
  - `TTL`: Time-to-live for cache entries
  - `EvictionPolicy`: LRU, LFU, or FIFO
- **L2 Cache**: File-based cache settings
  - `MaxSizeMB`: Maximum cache size in MB
  - `Compression`: Enable/disable compression
- **L3 Cache**: Redis cache settings
  - `RedisURL`: Redis connection URL
  - `KeyPrefix`: Prefix for cache keys

#### Concurrency Configuration
- `MaxWorkers`: Maximum number of worker goroutines
- `QueueSize`: Size of work queue
- `WorkerTimeout`: Timeout for individual workers
- `GracefulShutdown`: Enable graceful shutdown

#### Monitoring Configuration
- `MetricsInterval`: Frequency of metrics collection
- `AlertThresholds`: Thresholds for performance alerts
- `RetentionPeriod`: How long to keep metrics data

## Monitoring and Metrics

### Getting Statistics

```go
stats := optManager.GetOptimizationStats()

// Database statistics
fmt.Printf("Cache hit ratio: %.2f%%\n", stats.Database.CacheHitRatio*100)
fmt.Printf("Average query time: %v\n", stats.Database.AvgQueryTime)
fmt.Printf("Batch efficiency: %.2f%%\n", stats.Database.BatchEfficiency*100)

// Cache statistics
fmt.Printf("L1 hit ratio: %.2f%%\n", stats.Cache.L1HitRatio*100)
fmt.Printf("L2 hit ratio: %.2f%%\n", stats.Cache.L2HitRatio*100)
fmt.Printf("Overall hit ratio: %.2f%%\n", stats.Cache.OverallHitRatio*100)

// Performance statistics
fmt.Printf("Throughput: %.2f ops/sec\n", stats.Performance.Throughput)
fmt.Printf("Latency: %v\n", stats.Performance.Latency)
fmt.Printf("Optimization score: %.2f\n", stats.Performance.OptimizationScore)

// Resource statistics
fmt.Printf("CPU usage: %.2f%%\n", stats.Resource.CPUUsage)
fmt.Printf("Memory usage: %d MB\n", stats.Resource.MemoryUsage/(1024*1024))
fmt.Printf("Goroutines: %d\n", stats.Resource.GoroutineCount)
```

### Generating Reports

```go
report := optManager.GenerateOptimizationReport()

// View recommendations
for _, rec := range report.Recommendations {
    fmt.Printf("Recommendation: %s (Priority: %s)\n", rec.Description, rec.Priority)
    fmt.Printf("Expected impact: %s\n", rec.Impact)
}

// View alerts
for _, alert := range report.Alerts {
    fmt.Printf("Alert: %s (Severity: %s)\n", alert.Message, alert.Severity)
}

// View bottlenecks
for _, bottleneck := range report.Bottlenecks {
    fmt.Printf("Bottleneck in %s: %s\n", bottleneck.Component, bottleneck.Description)
}
```

### Health Monitoring

```go
// Perform health check
health := optManager.OptimizationHealthCheck()
fmt.Printf("Status: %s\n", health["status"])
fmt.Printf("Cache hit ratio: %s\n", health["cache_hit_ratio"])
fmt.Printf("Memory usage: %s\n", health["memory_usage"])
fmt.Printf("Optimization level: %s\n", health["optimization_level"])
```

## Performance Tuning

### Cache Optimization

1. **L1 Cache Tuning**:
   - Increase `MaxSize` for better hit ratios
   - Adjust `TTL` based on data freshness requirements
   - Choose appropriate eviction policy (LRU for temporal locality, LFU for frequency-based)

2. **L2 Cache Tuning**:
   - Set `MaxSizeMB` based on available disk space
   - Enable compression for better space utilization
   - Adjust `TTL` for longer-term caching

3. **L3 Cache Tuning**:
   - Configure Redis for optimal performance
   - Use appropriate `KeyPrefix` to avoid conflicts
   - Set `TTL` for distributed cache consistency

### Database Optimization

1. **Query Caching**:
   - Increase `QueryCacheSize` for frequently accessed data
   - Monitor cache hit ratios and adjust accordingly

2. **Batch Processing**:
   - Optimize `BatchSize` based on query complexity
   - Enable batching for bulk operations

3. **Connection Management**:
   - Set `MaxConnections` based on database capacity
   - Adjust timeouts based on network conditions

### Concurrency Optimization

1. **Worker Pool Tuning**:
   - Set `MaxWorkers` based on CPU cores and workload
   - Adjust `QueueSize` to handle traffic spikes

2. **Resource Management**:
   - Monitor goroutine count and memory usage
   - Enable graceful shutdown for clean termination

## Best Practices

### Production Deployment

1. **Configuration**:
   - Use environment-specific configurations
   - Validate configurations before deployment
   - Monitor configuration changes

2. **Monitoring**:
   - Set up alerts for performance degradation
   - Monitor cache hit ratios and adjust cache sizes
   - Track resource usage trends

3. **Maintenance**:
   - Regularly review optimization recommendations
   - Update configurations based on usage patterns
   - Perform periodic performance analysis

### Development and Testing

1. **Testing**:
   - Use test-specific configurations
   - Write performance benchmarks
   - Test with realistic data volumes

2. **Debugging**:
   - Enable detailed logging in development
   - Use profiling tools for performance analysis
   - Monitor resource usage during development

## Troubleshooting

### Common Issues

1. **Low Cache Hit Ratios**:
   - Check cache sizes and TTL settings
   - Verify cache warming is working
   - Review access patterns

2. **High Memory Usage**:
   - Reduce cache sizes
   - Enable compression
   - Check for memory leaks

3. **Poor Performance**:
   - Review optimization recommendations
   - Check for bottlenecks in the report
   - Adjust concurrency settings

4. **Database Timeouts**:
   - Increase connection and query timeouts
   - Check database performance
   - Review query complexity

### Debugging Tools

1. **Health Checks**:
   ```go
   health := optManager.OptimizationHealthCheck()
   if health["status"] != "healthy" {
       log.Printf("Optimization unhealthy: %s", health["reason"])
   }
   ```

2. **Performance Reports**:
   ```go
   report := optManager.GenerateOptimizationReport()
   for _, alert := range report.Alerts {
       log.Printf("Alert: %s", alert.Message)
   }
   ```

3. **Statistics Monitoring**:
   ```go
   stats := optManager.GetOptimizationStats()
   if stats.Performance.OptimizationScore < 0.7 {
       log.Println("Performance below threshold")
   }
   ```

## API Reference

### OptimizationManager

- `NewOptimizationManager(db, environment)`: Create new optimization manager
- `Start()`: Start optimization processes
- `Stop()`: Stop optimization processes
- `OptimizedThreatLookup(package, registry)`: Perform optimized threat lookup
- `BatchOptimizedThreatLookup(packages)`: Perform batch optimized lookups
- `GetOptimizationStats()`: Get current optimization statistics
- `GenerateOptimizationReport()`: Generate comprehensive optimization report
- `OptimizationHealthCheck()`: Perform health check
- `GetConfiguration()`: Get current configuration
- `UpdateConfiguration(config)`: Update configuration
- `IsRunning()`: Check if optimization is running

### Configuration Functions

- `ConfigFromEnvironment(env)`: Load configuration for environment
- `GetProductionConfig()`: Get production configuration
- `GetDevelopmentConfig()`: Get development configuration
- `GetTestConfig()`: Get test configuration
- `GetRecommendedConfig()`: Get system-optimized configuration
- `ValidateConfig(config)`: Validate configuration

### Convenience Functions

- `QuickOptimizationSetup(db)`: Quick setup with production settings
- `DevelopmentOptimizationSetup(db)`: Setup for development
- `TestOptimizationSetup(db)`: Setup for testing

## Examples

See `examples.go` for comprehensive usage examples including:
- Basic optimization setup
- Batch processing
- Advanced configuration
- Health monitoring
- Configuration management
- Performance benchmarking

## Testing

Run the test suite:

```bash
go test ./internal/optimization/...
```

Run benchmarks:

```bash
go test -bench=. ./internal/optimization/...
```

## Contributing

When contributing to the optimization system:

1. Write comprehensive tests for new features
2. Update documentation for configuration changes
3. Add benchmarks for performance-critical code
4. Follow the existing code style and patterns
5. Ensure backward compatibility when possible

## License

This optimization system is part of the Typosentinel project and follows the same license terms.