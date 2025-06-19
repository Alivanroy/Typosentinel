# Debug Logging and Verbose Modes

TypoSentinel provides comprehensive logging and debugging capabilities to help developers and security teams understand the analysis process and troubleshoot issues.

## Log Levels

TypoSentinel supports multiple log levels, from least to most verbose:

- **FATAL**: Critical errors that cause the application to exit
- **ERROR**: Error conditions that don't stop execution
- **WARN**: Warning messages for potentially problematic situations
- **INFO**: General informational messages
- **VERBOSE**: Detailed operational information
- **DEBUG**: Detailed debugging information
- **TRACE**: Most detailed tracing information including function calls

## Debug Modes

TypoSentinel offers several debug modes for different use cases:

### Basic Debug Mode
```bash
typosentinel scan lodash --debug
```
- Enables DEBUG log level
- Shows basic debugging information
- Includes error details and configuration info

### Verbose Mode
```bash
typosentinel scan lodash --verbose
```
- Enables VERBOSE log level
- Shows detailed operational information
- Includes analysis progress and results

### Trace Mode
```bash
typosentinel scan lodash --trace
```
- Enables TRACE log level
- Shows function entry/exit tracing
- Most detailed logging available

### Advanced Debug Modes

#### Performance Debug Mode
```bash
typosentinel scan lodash --debug-mode=performance
```
- Focuses on performance metrics
- Tracks timing information
- Memory usage monitoring
- CPU profiling data

#### Security Debug Mode
```bash
typosentinel scan lodash --debug-mode=security
```
- Security-focused debugging
- Detailed threat analysis logs
- Vulnerability detection traces
- Policy evaluation details

#### Comprehensive Debug Mode
```bash
typosentinel scan lodash --debug-mode=trace
```
- Combines all debug features
- Function call tracing
- Detailed context information
- Stack traces for errors

## CLI Flags

### Basic Flags
- `--debug`: Enable basic debug mode
- `--verbose`: Enable verbose logging
- `--trace`: Enable trace mode (most verbose)

### Advanced Flags
- `--debug-mode=MODE`: Set specific debug mode (basic, verbose, trace, performance, security)
- `--log-level=LEVEL`: Set log level explicitly (trace, verbose, debug, info, warn, error, fatal)
- `--log-format=FORMAT`: Set log format (text, json)
- `--log-output=OUTPUT`: Set log output (stdout, stderr, file path)

## Configuration File

You can configure logging in your configuration file:

```yaml
logging:
  level: "debug"          # Log level
  format: "json"          # Output format
  output: "stdout"        # Output destination
  timestamp: true         # Include timestamps
  caller: true           # Include caller information
  prefix: "[TypoSentinel]" # Log prefix
  
  # Log rotation (for file output)
  rotation:
    enabled: true
    max_size: 100         # MB
    max_backups: 5
    max_age: 30          # days
```

## Examples

### Basic Debugging
```bash
# Enable debug mode
typosentinel scan lodash --debug

# Enable verbose mode with JSON output
typosentinel scan lodash --verbose --log-format=json

# Save debug logs to file
typosentinel scan lodash --debug --log-output=./debug.log
```

### Advanced Debugging
```bash
# Performance debugging
typosentinel scan lodash --debug-mode=performance --log-format=json

# Security-focused debugging
typosentinel scan lodash --debug-mode=security --verbose

# Full trace with file output
typosentinel scan lodash --trace --log-output=./trace.log
```

### Configuration-based Debugging
```bash
# Use debug configuration file
typosentinel scan lodash --config=./examples/debug-config.yaml

# Override config with CLI flags
typosentinel scan lodash --config=./config.yaml --debug --log-format=json
```

## Debug Output Examples

### Text Format (Default)
```
[2024-01-15 10:30:15] INFO [TypoSentinel] Starting package scan package=lodash version=latest registry=npm
[2024-01-15 10:30:15] DEBUG [TypoSentinel] Scanner created successfully
[2024-01-15 10:30:16] VERBOSE [TypoSentinel] Starting static analysis package=lodash analyzer=*static.StaticAnalyzer
[2024-01-15 10:30:18] VERBOSE [TypoSentinel] Static analysis completed package=lodash duration=2.1s findings_count=3
```

### JSON Format
```json
{
  "timestamp": "2024-01-15T10:30:15Z",
  "level": "INFO",
  "message": "Starting package scan",
  "package": "lodash",
  "version": "latest",
  "registry": "npm"
}
{
  "timestamp": "2024-01-15T10:30:16Z",
  "level": "VERBOSE",
  "message": "Starting static analysis",
  "package": "lodash",
  "analyzer": "*static.StaticAnalyzer",
  "fail_fast": false
}
```

## Debug Context Information

When debug modes are enabled, TypoSentinel provides rich context information:

### Scanner Initialization
- Configuration details
- Enabled analysis engines
- Memory addresses for debugging
- Timing information

### Analysis Engine Details
- Engine types and configurations
- Analysis duration
- Finding counts and risk scores
- Error details with stack traces

### Performance Metrics
- Function execution times
- Memory usage patterns
- CPU utilization
- Cache hit/miss ratios

### Security Context
- Threat detection details
- Policy evaluation traces
- Vulnerability assessment steps
- Risk calculation factors

## Troubleshooting

### Common Issues

1. **Too Much Log Output**
   - Use `--quiet` flag to suppress non-essential output
   - Set specific log level: `--log-level=warn`
   - Use file output: `--log-output=./debug.log`

2. **Missing Debug Information**
   - Ensure debug mode is enabled: `--debug`
   - Check log level: `--log-level=debug`
   - Verify configuration file settings

3. **Performance Impact**
   - Debug modes can slow down execution
   - Use specific debug modes for targeted debugging
   - Disable debug modes in production

### Debug Best Practices

1. **Development**: Use `--debug` or `--verbose` for general debugging
2. **Performance Issues**: Use `--debug-mode=performance`
3. **Security Analysis**: Use `--debug-mode=security`
4. **Production Issues**: Use `--log-level=warn` with file output
5. **CI/CD**: Use `--quiet` with error-level logging

## Integration with Monitoring

The JSON log format is designed for integration with log aggregation systems:

- **ELK Stack**: Elasticsearch, Logstash, Kibana
- **Splunk**: Direct JSON ingestion
- **Prometheus**: Metrics extraction from logs
- **Grafana**: Log visualization and alerting

### Example Logstash Configuration
```ruby
input {
  file {
    path => "/var/log/typosentinel/*.log"
    codec => "json"
  }
}

filter {
  if [level] == "ERROR" or [level] == "FATAL" {
    mutate {
      add_tag => ["alert"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "typosentinel-%{+YYYY.MM.dd}"
  }
}
```

## Environment Variables

You can also control logging via environment variables:

```bash
export TYPOSENTINEL_LOG_LEVEL=debug
export TYPOSENTINEL_LOG_FORMAT=json
export TYPOSENTINEL_LOG_OUTPUT=./logs/typosentinel.log
export TYPOSENTINEL_DEBUG_MODE=performance

typosentinel scan lodash
```

## API Integration

When using TypoSentinel as an API, debug information is available through:

- Response headers with timing information
- Detailed error responses with debug context
- Optional debug endpoints for internal state
- WebSocket streams for real-time debug output

For more information, see the [API Documentation](./API.md).