# Edge Algorithms CLI Integration

This document describes the CLI integration for the novel edge algorithms in Typosentinel. The edge algorithms provide cutting-edge threat detection capabilities using advanced mathematical models and machine learning techniques.

## Overview

The edge algorithms are integrated into the main CLI through the `edge` command group, providing access to four sophisticated algorithms:

- **GTR** (Graph Traversal Risk) - Advanced graph-based dependency analysis
- **RUNT** (Recursive Universal Network Traversal) - Deep recursive analysis of package relationships
- **AICC** (Adaptive Intelligence Correlation Clustering) - Attestation consistency checking and policy violation detection
- **DIRT** (Dependency Impact Risk Traversal) - Cascading vulnerability propagation analysis

## Command Structure

```bash
typosentinel edge <algorithm> [packages...] [flags]
```

## Available Algorithms

### 1. GTR (Graph Traversal Risk)

Performs advanced graph-based analysis of package dependencies and relationships for sophisticated threat detection.

```bash
typosentinel edge gtr [packages...] [flags]
```

**Flags:**
- `--threshold <float>`: Risk threshold for GTR analysis (default: 0.7)
- `--max-depth <int>`: Maximum graph traversal depth (default: 5)
- `--include-metrics`: Include detailed metrics in output

**Example:**
```bash
typosentinel edge gtr lodash express --threshold 0.8 --max-depth 10 --include-metrics
```

**Output:**
- Threat Score: Calculated risk score based on graph analysis
- Confidence: Algorithm confidence percentage
- Processing Time: Analysis duration
- Attack Vectors: Identified potential attack paths
- Findings: Detailed security findings with severity levels

### 2. RUNT (Recursive Universal Network Traversal)

Performs deep recursive analysis of package dependencies and network relationships for comprehensive threat detection.

```bash
typosentinel edge runt [packages...] [flags]
```

**Flags:**
- `--max-depth <int>`: Maximum recursion depth (default: 10)
- `--similarity <float>`: Similarity threshold for analysis (default: 0.8)
- `--include-features`: Include feature analysis in output

**Example:**
```bash
typosentinel edge runt react vue --max-depth 15 --similarity 0.9 --include-features
```

**Output:**
- Threat Score: Risk assessment based on recursive analysis
- Confidence: Algorithm confidence percentage
- Processing Time: Analysis duration
- Attack Vectors: Identified threat vectors
- Findings: Security findings with evidence and remediation

### 3. AICC (Adaptive Intelligence Correlation Clustering)

Uses attestation internal consistency checking for advanced attestation chain forgery detection and policy violation detection.

```bash
typosentinel edge aicc [packages...] [flags]
```

**Flags:**
- `--clusters <int>`: Number of clusters for analysis (default: 5)
- `--adaptive`: Enable adaptive clustering mode
- `--include-correlation`: Include correlation metrics

**Example:**
```bash
typosentinel edge aicc webpack babel --clusters 8 --adaptive --include-correlation
```

**Output:**
- Threat Score: Attestation consistency risk score
- Confidence: Algorithm confidence percentage
- Processing Time: Analysis duration
- Attack Vectors: Potential attestation-based attacks
- Findings: Attestation violations and policy issues

### 4. DIRT (Dependency Impact Risk Traversal)

Analyzes dependency chains and impact propagation for comprehensive supply chain risk assessment.

```bash
typosentinel edge dirt [packages...] [flags]
```

**Flags:**
- `--max-depth <int>`: Maximum dependency traversal depth (default: 8)
- `--risk-threshold <float>`: Risk threshold for impact analysis (default: 0.6)
- `--include-graph`: Include dependency graph metrics

**Example:**
```bash
typosentinel edge dirt typescript eslint --max-depth 12 --risk-threshold 0.7 --include-graph
```

**Output:**
- Threat Score: Cascading risk assessment
- Confidence: Algorithm confidence percentage
- Processing Time: Analysis duration
- Attack Vectors: Supply chain attack vectors
- Findings: Dependency risks and impact analysis

## Benchmark Command

Run performance benchmarks on all edge algorithms with various test scenarios.

```bash
typosentinel edge benchmark [flags]
```

**Flags:**
- `--packages <int>`: Number of packages to benchmark (default: 100)
- `--workers <int>`: Number of concurrent workers (default: 4)
- `--iterations <int>`: Number of benchmark iterations (default: 3)

**Example:**
```bash
typosentinel edge benchmark --packages 500 --workers 8 --iterations 5
```

## Global Flags

All edge commands support these global flags:

- `--output <format>`, `-o <format>`: Output format (text, json) (default: text)
- `--help`, `-h`: Show help for the command

## Output Formats

### Text Format (Default)

Human-readable output with structured information:

```
📦 Package: lodash
Threat Score: 0.2500
Confidence: 85.00%
Processing Time: 1.2ms
Attack Vectors:
  - dependency_confusion
  - supply_chain_tampering
Findings:
  - [MEDIUM] Outdated dependency detected
  - [LOW] Development dependency in production
```

### JSON Format

Machine-readable JSON output for integration:

```bash
typosentinel edge gtr lodash --output json
```

```json
{
  "algorithm_name": "GTR",
  "tier": "G",
  "threat_score": 0.25,
  "confidence": 0.85,
  "attack_vectors": ["dependency_confusion", "supply_chain_tampering"],
  "findings": [
    {
      "type": "outdated_dependency",
      "severity": "MEDIUM",
      "description": "Outdated dependency detected",
      "evidence": {"version": "4.17.20", "latest": "4.17.21"},
      "remediation": "Update to latest version"
    }
  ],
  "metadata": {
    "dependencies_count": 15,
    "processing_time_ms": 1.2
  },
  "processing_time": "1.2ms",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Integration Examples

### CI/CD Pipeline Integration

```bash
#!/bin/bash
# Run edge algorithm analysis in CI/CD
packages=("lodash" "express" "react")

for pkg in "${packages[@]}"; do
    echo "Analyzing $pkg with all edge algorithms..."
    
    # GTR Analysis
    typosentinel edge gtr "$pkg" --output json > "gtr_$pkg.json"
    
    # RUNT Analysis
    typosentinel edge runt "$pkg" --output json > "runt_$pkg.json"
    
    # AICC Analysis
    typosentinel edge aicc "$pkg" --output json > "aicc_$pkg.json"
    
    # DIRT Analysis
    typosentinel edge dirt "$pkg" --output json > "dirt_$pkg.json"
done

# Run comprehensive benchmark
typosentinel edge benchmark --packages 200 --workers 4
```

### Security Audit Script

```bash
#!/bin/bash
# Comprehensive security audit using edge algorithms

echo "🔍 Starting comprehensive security audit..."

# High-sensitivity analysis
typosentinel edge gtr package.json --threshold 0.9 --max-depth 15 --include-metrics

# Deep dependency analysis
typosentinel edge runt package.json --max-depth 20 --similarity 0.95 --include-features

# Attestation verification
typosentinel edge aicc package.json --clusters 10 --adaptive --include-correlation

# Supply chain risk assessment
typosentinel edge dirt package.json --max-depth 15 --risk-threshold 0.8 --include-graph

echo "✅ Security audit complete!"
```

## Performance Characteristics

### Algorithm Performance

| Algorithm | Avg Time/Package | Throughput (pkg/sec) | Memory Usage |
|-----------|------------------|---------------------|--------------|
| GTR       | 0.5ms           | 2000               | Low          |
| RUNT      | 1.2ms           | 833                | Medium       |
| AICC      | 0.3ms           | 3333               | Low          |
| DIRT      | 0.8ms           | 1250               | Medium       |

### Concurrent Performance

The edge algorithms support concurrent processing with excellent scalability:

- **4 workers**: 200 packages in ~12ms
- **8 workers**: 400 packages in ~18ms
- **16 workers**: 800 packages in ~25ms

## Error Handling

The CLI provides comprehensive error handling:

```bash
# Invalid package
typosentinel edge gtr invalid-package
# Output: Error analyzing invalid-package: package not found

# Invalid threshold
typosentinel edge gtr lodash --threshold 1.5
# Output: Error: threshold must be between 0.0 and 1.0

# Network timeout
typosentinel edge runt package --max-depth 100
# Output: Error analyzing package: analysis timeout exceeded
```

## Best Practices

### 1. Algorithm Selection

- **GTR**: Use for dependency graph analysis and attack path detection
- **RUNT**: Use for deep recursive analysis and similarity detection
- **AICC**: Use for attestation verification and policy compliance
- **DIRT**: Use for supply chain risk assessment and impact analysis

### 2. Performance Optimization

- Use appropriate depth limits for large dependency trees
- Enable caching for repeated analyses
- Use concurrent workers for batch processing
- Monitor memory usage for large-scale analyses

### 3. Security Considerations

- Validate all input packages before analysis
- Use secure network connections for package metadata
- Implement rate limiting for API calls
- Log all security findings for audit trails

## Troubleshooting

### Common Issues

1. **Package Not Found**
   - Verify package name and registry
   - Check network connectivity
   - Ensure registry access permissions

2. **Analysis Timeout**
   - Reduce max-depth parameter
   - Increase timeout configuration
   - Check system resources

3. **Memory Issues**
   - Reduce concurrent workers
   - Limit analysis depth
   - Monitor system memory usage

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
export LOG_LEVEL=debug
typosentinel edge gtr lodash --threshold 0.8
```

## Future Enhancements

- **Real-time Analysis**: Stream processing for continuous monitoring
- **Custom Algorithms**: Plugin system for custom edge algorithms
- **Advanced Visualization**: Graph visualization for dependency analysis
- **Machine Learning**: Enhanced ML models for threat prediction
- **Integration APIs**: REST APIs for external system integration

## Support

For issues, questions, or feature requests related to edge algorithms CLI:

1. Check the [troubleshooting section](#troubleshooting)
2. Review the [examples](#integration-examples)
3. Submit issues to the project repository
4. Consult the [API documentation](API_REFERENCE.md)

---

*This documentation covers the edge algorithms CLI integration. For general CLI usage, see the main [User Guide](USER_GUIDE.md).*