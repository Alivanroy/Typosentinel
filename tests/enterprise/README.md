# TypoSentinel Enterprise Network Testing Environment

This directory contains a comprehensive Docker-based testing environment designed to simulate real-world enterprise scenarios, from basic typosquatting attacks to sophisticated nation-state level cyber threats.

## Overview

The enterprise testing environment provides:

- **Realistic Attack Simulation**: From simple typosquatting to advanced APT campaigns
- **Scalable Testing Infrastructure**: Docker-based microservices architecture
- **Comprehensive Monitoring**: Prometheus, Grafana, and Elasticsearch integration
- **Performance Benchmarking**: Load testing and stress testing capabilities
- **Enterprise Compliance**: Testing against enterprise security standards
- **Detailed Reporting**: JSON, HTML, and PDF report generation

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Enterprise Test Network                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  TypoSentinel   │  │ Attack Simulator│  │ Malicious C2    │ │
│  │    Scanner      │  │    Engine       │  │   Simulator     │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Package Registry│  │   PostgreSQL    │  │     Redis       │ │
│  │   Simulators    │  │    Database     │  │     Cache       │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Elasticsearch  │  │   Prometheus    │  │     Grafana     │ │
│  │     Search      │  │   Monitoring    │  │  Visualization  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Python 3.8+ (for running test scripts)
- At least 8GB RAM and 20GB disk space

### Running Enterprise Tests

1. **Basic Test Suite**:
   ```bash
   cd /Users/alikorsi/Documents/Typosentinel/tests/enterprise
   python run_enterprise_tests.py --intensity medium
   ```

2. **Specific Attack Category**:
   ```bash
   python run_enterprise_tests.py --category typosquatting --intensity high
   ```

3. **Full Enterprise Suite**:
   ```bash
   python run_enterprise_tests.py --intensity enterprise --category all
   ```

4. **Performance Testing Only**:
   ```bash
   python run_enterprise_tests.py --category performance --intensity high
   ```

## Test Categories

### 1. Typosquatting Attacks

Simulates various typosquatting techniques:

- **Basic Typos**: Character substitution, omission, insertion
- **Advanced Typos**: Homoglyph substitution, combosquatting
- **Sophisticated Typos**: AI-generated variants, steganographic naming

Example packages tested:
- `reqeusts` (typo of `requests`)
- `nump1` (homoglyph of `numpy`)
- `flask-security` (combosquatting)

### 2. Supply Chain Attacks

Tests supply chain compromise scenarios:

- **Dependency Confusion**: Internal package name conflicts
- **Malicious Updates**: Compromised legitimate packages
- **Compromised Maintainers**: Account takeover scenarios

### 3. Nation-State Level Attacks

Simulates sophisticated APT campaigns:

- **APT Groups**: APT28, APT29, APT40, Lazarus, Equation Group
- **Zero-Day Exploits**: Kernel, hypervisor, firmware vulnerabilities
- **Critical Infrastructure**: Energy, water, transportation targeting

### 4. Advanced Persistent Threats

Long-term campaign simulation:

- **Multi-Stage Attacks**: Dropper → Loader → Payload chains
- **AI-Powered Attacks**: ML model poisoning, adversarial examples
- **Long-Term Campaigns**: 6-24 month attack simulations

### 5. Quantum-Era Attacks

Next-generation threat simulation:

- **Quantum Cryptographic Attacks**: Post-quantum crypto bypass
- **Quantum Network Attacks**: QKD network targeting

## Configuration

### Test Intensity Levels

| Level | Concurrent Attacks | Duration | Use Case |
|-------|-------------------|----------|----------|
| Low | 5 | 1 hour | Development testing |
| Medium | 15 | 4 hours | CI/CD integration |
| High | 30 | 8 hours | Pre-production validation |
| Enterprise | 50 | 24 hours | Production readiness |

### Enterprise Environments

The testing framework supports different enterprise environments:

- **Financial Services**: PCI-DSS, SOX compliance testing
- **Healthcare**: HIPAA, FDA compliance validation
- **Technology**: SOC2, ISO27001 standards
- **Government**: FedRAMP, FISMA requirements

## Performance Metrics

### Detection Metrics
- **Detection Rate**: Percentage of malicious packages detected
- **False Positive Rate**: Legitimate packages flagged as malicious
- **Response Time**: Time to analyze and classify packages
- **Throughput**: Packages processed per hour

### Enterprise Standards
- Minimum 95% detection rate
- Maximum 5% false positive rate
- Maximum 5 seconds response time
- Minimum 1000 packages/hour throughput

## Monitoring and Observability

### Prometheus Metrics
- Request rates and response times
- Error rates and success rates
- Resource utilization (CPU, memory, disk)
- Detection accuracy metrics

### Grafana Dashboards
- Real-time attack simulation status
- Performance metrics visualization
- Enterprise compliance tracking
- Alert management

### Elasticsearch Logging
- Detailed attack scenario logs
- Detection result analysis
- Performance trend analysis
- Compliance audit trails

## Report Generation

### Report Types

1. **Executive Summary**: High-level results for management
2. **Technical Report**: Detailed analysis for security teams
3. **Compliance Report**: Regulatory compliance assessment
4. **Performance Report**: Benchmarking and optimization insights

### Report Formats
- JSON: Machine-readable results
- HTML: Interactive web reports
- PDF: Printable executive summaries

## Advanced Usage

### Custom Attack Scenarios

Create custom scenarios in `scenarios/custom_scenarios.yaml`:

```yaml
custom_attacks:
  financial_targeted:
    count: 20
    severity: critical
    description: "Financial sector targeted attacks"
    target_packages:
      - banking-apis
      - payment-processing
      - crypto-wallets
```

### Integration with CI/CD

Add to your CI/CD pipeline:

```yaml
# .github/workflows/security-testing.yml
- name: Run Enterprise Security Tests
  run: |
    cd tests/enterprise
    python run_enterprise_tests.py --intensity medium --category all
    if [ $? -ne 0 ]; then exit 1; fi
```

### Custom Performance Testing

```bash
# High-intensity load testing
python attack-simulator/performance_tester.py \
  --test-type load \
  --concurrent 100 \
  --total 5000 \
  --delay 0.05
```

## Troubleshooting

### Common Issues

1. **Docker Memory Issues**:
   ```bash
   # Increase Docker memory allocation to 8GB+
   docker system prune -a
   ```

2. **Port Conflicts**:
   ```bash
   # Check for port conflicts
   netstat -tulpn | grep :8080
   ```

3. **Service Startup Failures**:
   ```bash
   # Check service logs
   docker-compose -f docker-compose.enterprise-test.yml logs attack-simulator
   ```

### Performance Optimization

1. **Increase Concurrent Connections**:
   ```yaml
   # In docker-compose.enterprise-test.yml
   environment:
     - MAX_WORKERS=50
     - CONNECTION_POOL_SIZE=100
   ```

2. **Optimize Database Performance**:
   ```yaml
   postgres:
     environment:
       - POSTGRES_SHARED_BUFFERS=256MB
       - POSTGRES_EFFECTIVE_CACHE_SIZE=1GB
   ```

## Security Considerations

### Isolated Testing Environment

- All tests run in isolated Docker networks
- No external network access for malicious simulators
- Encrypted communication between services
- Automatic cleanup of test artifacts

### Data Protection

- No real credentials or sensitive data used
- Synthetic test data generation
- Secure disposal of test results
- Compliance with data retention policies

## Contributing

### Adding New Attack Scenarios

1. Create scenario definition in `scenarios/`
2. Implement generator in `attack-simulator/`
3. Add test cases in `tests/`
4. Update documentation

### Performance Improvements

1. Profile bottlenecks using built-in metrics
2. Optimize database queries
3. Implement caching strategies
4. Scale horizontally with additional containers

## License

This enterprise testing framework is part of the TypoSentinel project and follows the same licensing terms.

## Support

For enterprise support and custom testing scenarios:
- Create issues in the main TypoSentinel repository
- Contact the security team for compliance questions
- Review monitoring dashboards for operational insights