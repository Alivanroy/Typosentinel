# TypoSentinel Enhanced Logging System

This package provides a comprehensive, configurable logging system for TypoSentinel with support for structured logging, multiple output formats, log rotation, and flexible configuration.

## Features

- **Multiple Log Levels**: DEBUG, INFO, WARN, ERROR
- **Structured Logging**: Support for key-value pairs and JSON output
- **Configurable Output**: Console (stdout/stderr) or file output
- **Log Rotation**: Automatic log file rotation with size and age limits
- **Global and Instance Loggers**: Use global functions or create custom logger instances
- **Field Loggers**: Create loggers with predefined fields for consistent context
- **Configuration Integration**: Seamless integration with TypoSentinel's configuration system

## Quick Start

### Basic Usage

```go
import "typosentinel/pkg/logger"

// Simple logging
logger.Info("Application started")
logger.Error("Something went wrong")

// Formatted logging
logger.Infof("Processing %d packages", count)
logger.Errorf("Failed to connect to %s", endpoint)
```

### Structured Logging

```go
// Logging with structured fields
logger.Info("Package scan completed", map[string]interface{}{
    "package_name": "lodash",
    "version": "4.17.21",
    "scan_duration": "2.5s",
    "findings_count": 3,
})

logger.Error("Database connection failed", map[string]interface{}{
    "error": err.Error(),
    "host": "localhost",
    "port": 5432,
    "retry_count": 3,
})
```

### Field Loggers

```go
// Create a logger with predefined fields
scanLogger := logger.GetGlobalLogger().WithFields(map[string]interface{}{
    "scan_id": "scan-123",
    "component": "static-analyzer",
})

// All log messages will include the predefined fields
scanLogger.Info("Starting analysis")
scanLogger.Error("Analysis failed")
```

## Configuration

### YAML Configuration

Add the following to your `config.yaml`:

```yaml
logging:
  level: "info"              # debug, info, warn, error
  format: "text"             # text or json
  output: "stdout"           # stdout, stderr, or file path
  timestamp: true            # include timestamps
  caller: false              # include caller information
  prefix: "[TYPOSENTINEL]"   # log prefix
  rotation:
    enabled: false           # enable log rotation
    max_size: 100           # maximum size in MB
    max_backups: 3          # number of backup files
    max_age: 28             # maximum age in days
    compress: true          # compress rotated files
```

### Programmatic Configuration

```go
// Initialize with custom configuration
config := logger.Config{
    Level:     logger.INFO,
    Format:    "json",
    Output:    os.Stdout,
    Timestamp: true,
    Caller:    true,
    Prefix:    "[MYAPP]",
}

customLogger := logger.NewWithConfig(config)
```

### File Output with Rotation

```yaml
logging:
  level: "info"
  format: "json"
  output: "/var/log/typosentinel/app.log"
  rotation:
    enabled: true
    max_size: 100    # 100MB per file
    max_backups: 5   # keep 5 backup files
    max_age: 30      # delete files older than 30 days
    compress: true   # compress old files
```

## Log Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| DEBUG | Detailed diagnostic information | Development, troubleshooting |
| INFO  | General informational messages | Normal application flow |
| WARN  | Warning messages for potentially harmful situations | Recoverable errors, deprecated usage |
| ERROR | Error messages for serious problems | Application errors, failures |

## Output Formats

### Text Format (Default)

```
2024-01-15 10:30:45 [TYPOSENTINEL] INFO: Package scan completed package_name=lodash version=4.17.21
2024-01-15 10:30:46 [TYPOSENTINEL] ERROR: Database connection failed error="connection refused" host=localhost
```

### JSON Format

```json
{"timestamp":"2024-01-15T10:30:45Z","level":"INFO","message":"Package scan completed","package_name":"lodash","version":"4.17.21"}
{"timestamp":"2024-01-15T10:30:46Z","level":"ERROR","message":"Database connection failed","error":"connection refused","host":"localhost"}
```

## Command Line Integration

The logging system integrates with TypoSentinel's command line flags:

```bash
# Enable debug logging
typosentinel scan --debug lodash

# Enable verbose logging
typosentinel scan --verbose lodash

# Use custom config file
typosentinel scan --config /path/to/config.yaml lodash
```

## Advanced Usage

### Dynamic Log Level Changes

```go
// Change global log level at runtime
logger.SetGlobalLevel(logger.DEBUG)

// Change global format at runtime
logger.SetGlobalFormat("json")
```

### Custom Logger Instances

```go
// Create a logger for a specific component
config := logger.DefaultConfig()
config.Prefix = "[SCANNER]"
config.Level = logger.DEBUG

scannerLogger := logger.NewWithConfig(config)
scannerLogger.Info("Scanner initialized")
```

### Testing Setup

```go
// Initialize logger for testing
logger.InitForTesting()

// Or with custom test configuration
logger.InitWithLevel(logger.DEBUG)
```

## Performance Considerations

- **Structured Fields**: Only computed when the log level is enabled
- **File I/O**: Buffered writes for better performance
- **Log Rotation**: Handled asynchronously to avoid blocking
- **JSON Marshaling**: Optimized for common field types

## Best Practices

1. **Use Appropriate Log Levels**:
   - DEBUG: Detailed tracing information
   - INFO: Important business logic events
   - WARN: Recoverable errors or deprecated usage
   - ERROR: Serious application errors

2. **Include Relevant Context**:
   ```go
   logger.Info("Package analysis started", map[string]interface{}{
       "package_name": pkg.Name,
       "version": pkg.Version,
       "registry": pkg.Registry,
       "scan_id": scanID,
   })
   ```

3. **Use Field Loggers for Components**:
   ```go
   componentLogger := logger.GetGlobalLogger().WithFields(map[string]interface{}{
       "component": "ml-analyzer",
       "version": "1.0.0",
   })
   ```

4. **Log Performance Metrics**:
   ```go
   start := time.Now()
   // ... do work ...
   logger.Info("Operation completed", map[string]interface{}{
       "operation": "package_scan",
       "duration": time.Since(start).String(),
       "success": true,
   })
   ```

5. **Handle Errors Gracefully**:
   ```go
   if err != nil {
       logger.Error("Operation failed", map[string]interface{}{
           "error": err.Error(),
           "operation": "fetch_package",
           "package_name": pkgName,
       })
       return err
   }
   ```

## Migration from Standard Log

If you're migrating from Go's standard `log` package:

```go
// Old
log.Printf("Processing package: %s", pkgName)
log.Printf("Error: %v", err)

// New
logger.Infof("Processing package: %s", pkgName)
logger.Error("Operation failed", map[string]interface{}{
    "error": err.Error(),
    "package_name": pkgName,
})
```

## Dependencies

- `gopkg.in/natefinch/lumberjack.v2`: Log rotation support
- Standard library packages: `log`, `fmt`, `encoding/json`, `io`, `os`

## Examples

See `examples/logging_example.go` for comprehensive usage examples.