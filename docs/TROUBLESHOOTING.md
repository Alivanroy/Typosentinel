# TypoSentinel Troubleshooting Guide

This guide helps you diagnose and resolve common issues when using TypoSentinel.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Problems](#configuration-problems)
- [Scanning Issues](#scanning-issues)
- [Performance Problems](#performance-problems)
- [API Issues](#api-issues)
- [Integration Problems](#integration-problems)
- [Error Messages](#error-messages)
- [Debug Mode](#debug-mode)
- [Getting Help](#getting-help)

## Installation Issues

### Binary Installation

**Problem**: Downloaded binary doesn't execute
```bash
./typosentinel: permission denied
```

**Solution**: Make the binary executable
```bash
chmod +x typosentinel
```

**Problem**: Binary not found in PATH
```bash
typosentinel: command not found
```

**Solutions**:
1. Use full path: `./typosentinel`
2. Add to PATH: `export PATH=$PATH:/path/to/typosentinel`
3. Move to system PATH: `sudo mv typosentinel /usr/local/bin/`

### Building from Source

**Problem**: Go version compatibility
```bash
go: module requires Go 1.23 or later
```

**Solution**: Update Go to version 1.23 or later
```bash
# Check current version
go version

# Update Go (varies by OS)
# macOS with Homebrew:
brew install go

# Linux:
wget https://golang.org/dl/go1.23.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
```

**Problem**: Build fails with dependency errors
```bash
go: module lookup disabled by GOPROXY=off
```

**Solution**: Enable Go module proxy
```bash
go env -w GOPROXY=https://proxy.golang.org,direct
go mod download
go build
```

### Docker Issues

**Problem**: Docker image fails to start
```bash
docker: Error response from daemon: failed to create shim
```

**Solutions**:
1. Check Docker daemon is running: `docker info`
2. Restart Docker service
3. Check available disk space: `df -h`
4. Pull latest image: `docker pull typosentinel:latest`

## Configuration Problems

### Configuration File Not Found

**Problem**: 
```bash
Error: configuration file not found
```

**Solutions**:
1. Create default config: `typosentinel config init`
2. Specify config path: `typosentinel --config /path/to/config.yaml scan`
3. Check current directory for `typosentinel.yaml`

### Invalid Configuration Format

**Problem**:
```bash
Error: invalid configuration format
```

**Solution**: Validate YAML syntax
```bash
# Check YAML syntax
python3 -c "import yaml; yaml.safe_load(open('typosentinel.yaml'))"

# Or use online YAML validator
# Common issues:
# - Incorrect indentation (use spaces, not tabs)
# - Missing quotes around special characters
# - Invalid boolean values (use true/false, not yes/no)
```

### Permission Issues

**Problem**: Cannot read/write configuration
```bash
Error: permission denied reading config file
```

**Solution**: Fix file permissions
```bash
# Make config readable
chmod 644 typosentinel.yaml

# For config directory
chmod 755 ~/.typosentinel/
```

## Scanning Issues

### No Packages Found

**Problem**: Scanner reports no packages found in project

**Solutions**:
1. **Check file patterns**: Ensure your project has recognizable dependency files
   ```bash
   # npm projects need:
   package.json
   
   # Python projects need:
   requirements.txt, setup.py, pyproject.toml, or Pipfile
   
   # Go projects need:
   go.mod
   ```

2. **Verify working directory**:
   ```bash
   # Run from project root
   cd /path/to/your/project
   typosentinel scan .
   ```

3. **Check file permissions**:
   ```bash
   # Ensure files are readable
   ls -la package.json requirements.txt go.mod
   ```

### False Positives

**Problem**: Legitimate packages flagged as suspicious

**Solutions**:
1. **Add to allowlist**:
   ```yaml
   # typosentinel.yaml
   allowlist:
     packages:
       - "legitimate-package-name"
       - "another-safe-package"
   ```

2. **Adjust similarity threshold**:
   ```yaml
   detection:
     similarity_threshold: 0.8  # Increase to reduce false positives
   ```

3. **Review detection methods**:
   ```yaml
   detection:
     methods:
       string_similarity: true
       visual_similarity: false  # Disable if causing issues
       ml_detection: true
   ```

### Network Issues

**Problem**: Cannot fetch package information
```bash
Error: failed to fetch package metadata: dial tcp: lookup registry.npmjs.org: no such host
```

**Solutions**:
1. **Check internet connection**: `ping registry.npmjs.org`
2. **Configure proxy** (if behind corporate firewall):
   ```yaml
   network:
     proxy: "http://proxy.company.com:8080"
     timeout: 30s
   ```
3. **Use offline mode**:
   ```bash
   typosentinel scan --offline .
   ```

## Performance Problems

### Slow Scanning

**Problem**: Scanning takes too long

**Solutions**:
1. **Increase concurrency**:
   ```yaml
   performance:
     max_workers: 10  # Increase based on CPU cores
     batch_size: 100
   ```

2. **Enable caching**:
   ```yaml
   cache:
     enabled: true
     ttl: 24h
     directory: "~/.typosentinel/cache"
   ```

3. **Exclude unnecessary files**:
   ```yaml
   scanning:
     exclude_patterns:
       - "node_modules/**"
       - "vendor/**"
       - "*.test.js"
   ```

### High Memory Usage

**Problem**: TypoSentinel consumes too much memory

**Solutions**:
1. **Reduce batch size**:
   ```yaml
   performance:
     batch_size: 50  # Reduce from default
   ```

2. **Limit concurrent workers**:
   ```yaml
   performance:
     max_workers: 4  # Reduce based on available RAM
   ```

3. **Disable memory-intensive features**:
   ```yaml
   detection:
     ml_detection: false  # Disable ML if not needed
   ```

## API Issues

### API Server Won't Start

**Problem**:
```bash
Error: failed to start API server: listen tcp :8080: bind: address already in use
```

**Solutions**:
1. **Change port**:
   ```bash
   typosentinel api --port 8081
   ```

2. **Find and kill process using port**:
   ```bash
   # Find process
   lsof -i :8080
   
   # Kill process
   kill -9 <PID>
   ```

3. **Use different interface**:
   ```bash
   typosentinel api --host 127.0.0.1 --port 8080
   ```

### Authentication Issues

**Problem**: API returns 401 Unauthorized

**Solutions**:
1. **Check API key**:
   ```bash
   curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:8080/api/v1/scan
   ```

2. **Verify API key in config**:
   ```yaml
   api:
     auth:
       enabled: true
       api_keys:
         - "your-secret-api-key"
   ```

### Request Timeout

**Problem**: API requests timeout

**Solutions**:
1. **Increase timeout**:
   ```yaml
   api:
     timeout: 300s  # 5 minutes
   ```

2. **Use async scanning**:
   ```bash
   curl -X POST http://localhost:8080/api/v1/scan/async \
        -H "Content-Type: application/json" \
        -d '{"path": "/path/to/project"}'
   ```

## Integration Problems

### CI/CD Integration

**Problem**: TypoSentinel fails in CI pipeline

**Solutions**:
1. **Check exit codes**:
   ```bash
   # Allow non-zero exit for warnings
   typosentinel scan . || [ $? -eq 1 ]
   ```

2. **Use appropriate output format**:
   ```bash
   # For CI systems that parse JSON
   typosentinel scan --output json --output-file results.json .
   ```

3. **Set appropriate thresholds**:
   ```yaml
   reporting:
     fail_on_suspicious: false  # Don't fail CI on suspicious packages
     fail_on_malicious: true    # Only fail on confirmed malicious
   ```

### IDE Integration

**Problem**: IDE plugin not working

**Solutions**:
1. **Check TypoSentinel in PATH**:
   ```bash
   which typosentinel
   ```

2. **Verify plugin configuration**:
   - Check IDE plugin settings
   - Ensure correct path to TypoSentinel binary
   - Verify workspace configuration

## Error Messages

### Common Error Patterns

#### "context deadline exceeded"
**Cause**: Network timeout or slow response
**Solution**: Increase timeout in configuration
```yaml
network:
  timeout: 60s
```

#### "too many open files"
**Cause**: System file descriptor limit reached
**Solution**: Increase system limits
```bash
# Temporary fix
ulimit -n 4096

# Permanent fix (add to ~/.bashrc or ~/.zshrc)
echo "ulimit -n 4096" >> ~/.bashrc
```

#### "invalid character in JSON"
**Cause**: Malformed JSON in API request/response
**Solution**: Validate JSON format
```bash
# Check JSON syntax
echo '{"your": "json"}' | python3 -m json.tool
```

#### "package not found in registry"
**Cause**: Package doesn't exist or registry is unreachable
**Solution**: 
1. Verify package name spelling
2. Check registry availability
3. Use offline mode if needed

## Debug Mode

### Enabling Debug Logging

```bash
# Command line
typosentinel --debug scan .

# Environment variable
export TYPOSENTINEL_DEBUG=true
typosentinel scan .

# Configuration file
echo "debug: true" >> typosentinel.yaml
```

### Debug Output Analysis

**Look for these patterns in debug logs**:

1. **Network issues**:
   ```
   DEBUG: HTTP request failed: dial tcp: i/o timeout
   ```

2. **Configuration problems**:
   ```
   DEBUG: Config validation failed: invalid threshold value
   ```

3. **Performance bottlenecks**:
   ```
   DEBUG: Package analysis took 5.2s (threshold: 1s)
   ```

### Collecting Debug Information

```bash
# Generate comprehensive debug report
typosentinel debug-info > debug-report.txt

# Include system information
typosentinel debug-info --include-system > full-debug-report.txt
```

## Getting Help

### Before Asking for Help

1. **Check this troubleshooting guide**
2. **Search existing issues**: [GitHub Issues](https://github.com/Alivanroy/Typosentinel/issues)
3. **Review documentation**: [User Guide](USER_GUIDE.md)
4. **Enable debug mode** and collect logs

### When Reporting Issues

Include the following information:

1. **TypoSentinel version**: `typosentinel --version`
2. **Operating system**: `uname -a`
3. **Go version** (if building from source): `go version`
4. **Configuration file** (remove sensitive data)
5. **Complete error message** and stack trace
6. **Steps to reproduce** the issue
7. **Debug logs** (if applicable)

### Support Channels

- **GitHub Issues**: [Report bugs and request features](https://github.com/Alivanroy/Typosentinel/issues/new/choose)
- **GitHub Discussions**: [Community support and questions](https://github.com/Alivanroy/Typosentinel/discussions)
- **Documentation**: [Complete documentation](https://github.com/Alivanroy/Typosentinel/tree/main/docs)

### Emergency Security Issues

For critical security vulnerabilities, please:
1. **DO NOT** create a public issue
2. Follow our [Security Policy](../SECURITY.md)
3. Report privately via [GitHub Security Advisories](https://github.com/Alivanroy/Typosentinel/security/advisories/new)

---

*This troubleshooting guide is regularly updated. If you encounter an issue not covered here, please [contribute](../CONTRIBUTING.md) by submitting a pull request with the solution.*