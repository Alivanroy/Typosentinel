# Docker Dynamic Analysis Fix Guide

## Problem Description

The TypoSentinel dynamic analysis was failing with the error:
```
Warning: dynamic analysis failed: failed to create sandbox: failed to create Docker container: exit status 125
```

## Root Cause Analysis

The issue was caused by two main problems:

1. **Missing Docker Image**: The required `ubuntu:20.04` Docker image was not available locally
2. **Missing Configuration**: The `SandboxImage` field was not properly configured in the default configuration files

## Solution Implemented

### 1. Docker Image Availability

The dynamic analysis requires the `ubuntu:20.04` Docker image. If not available locally, it needs to be pulled:

```bash
docker pull ubuntu:20.04
```

### 2. Configuration Updates

Updated the following configuration files to include the missing `sandbox_image` field:

#### `/config.yaml`
```yaml
# Dynamic Analysis Configuration
dynamic_analysis:
  enabled: true
  sandbox_type: "docker"
  sandbox_image: "ubuntu:20.04"  # Added this line
  sandbox_timeout: "5m"
  memory_limit: 512
  network_isolation: true
  file_system_monitoring: true
```

#### `/configs/enhanced.yaml`
```yaml
# Dynamic Analysis Configuration
dynamic_analysis:
  enabled: true
  sandbox_type: "docker"
  sandbox_image: "ubuntu:20.04"  # Added this line
  sandbox_timeout: "5m"
  memory_limit: 512
  network_isolation: true
  file_system_monitoring: true
```

#### `/internal/config/enhanced.go`
```go
DynamicAnalysis: &DynamicAnalysisConfig{
    Enabled: true,
    SandboxType: "docker",
    SandboxImage: "ubuntu:20.04",  // Added this line
    Timeout: "2m",
    MaxMemory: "512MB",
    MaxCPU: "1",
    NetworkIsolation: true,
    FileSystemIsolation: true,
    // ... rest of config
}
```

### 3. Enhanced Error Reporting

Improved error handling in `/internal/dynamic/sandbox.go` to provide more detailed error information:

```go
output, err := cmd.CombinedOutput()
if err != nil {
    return fmt.Errorf("failed to create Docker container with image %s: %w\nCommand: %s\nOutput: %s", 
        da.config.SandboxImage, err, cmd.String(), string(output))
}
```

## Testing the Fix

### 1. Verify Docker Image
```bash
docker images ubuntu:20.04
```

### 2. Test Container Creation
```bash
docker run -d --name test-sandbox --rm --network none --memory 536870912 --cpus 0.5 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=100m --tmpfs /var/tmp:rw,noexec,nosuid,size=100m --security-opt no-new-privileges:true --cap-drop ALL --user nobody ubuntu:20.04 sleep 300
```

### 3. Test TypoSentinel Scan
```bash
./typosentinel-cli scan express --verbose --config configs/enhanced.yaml
```

## Expected Results

After applying the fix:
- Dynamic analysis should run without Docker container creation errors
- Scans should complete successfully with all analysis engines (ml, provenance, dynamic)
- No more "exit status 125" errors

## Docker Container Security Features

The dynamic analysis uses the following security constraints for the Docker sandbox:

- **Network Isolation**: `--network none`
- **Memory Limit**: `--memory 536870912` (512MB)
- **CPU Limit**: `--cpus 0.5`
- **Read-only Filesystem**: `--read-only`
- **Temporary Filesystems**: `--tmpfs` for `/tmp` and `/var/tmp`
- **Security Options**: `--security-opt no-new-privileges:true`
- **Capability Drop**: `--cap-drop ALL`
- **User Restriction**: `--user nobody`
- **Auto-cleanup**: `--rm`

## Troubleshooting

If you encounter similar issues:

1. **Check Docker Status**: Ensure Docker daemon is running
2. **Verify Image**: Confirm the required image is available locally
3. **Check Configuration**: Ensure `sandbox_image` is set in config files
4. **Review Logs**: Use the enhanced error messages for debugging
5. **Test Manually**: Try creating a container manually with the same parameters

## Prevention

To prevent similar issues in the future:

1. Include Docker image pulling in deployment scripts
2. Add configuration validation for required fields
3. Implement health checks for dynamic analysis components
4. Document all required Docker images and their purposes