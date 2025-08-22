# Zero-Day Attack Scenarios for Typosentinel Testing

This directory contains comprehensive zero-day attack simulation scripts designed to test Typosentinel's detection capabilities across multiple package registries and attack vectors.

## Overview

The zero-day scenarios simulate realistic attack patterns that security tools must be able to detect, including:

- **Typosquatting Attacks**: Malicious packages with names similar to popular legitimate packages
- **Dependency Confusion**: Attacks targeting internal package naming conventions
- **Supply Chain Attacks**: Sophisticated attacks on the software supply chain

## Files Structure

```
zero-day-scenarios/
├── README.md                           # This documentation
├── test-config.json                    # Comprehensive test configuration
├── run-all-scenarios.sh               # Master orchestration script
├── typosquatting-attack.js            # Typosquatting simulation script
├── dependency-confusion-attack.py     # Dependency confusion simulation
├── supply-chain-attack.rb             # Supply chain attack simulation
└── comprehensive-attack-report/       # Generated reports (created during execution)
```

## Prerequisites

### System Requirements
- **Operating System**: macOS, Linux, or Windows with WSL
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Storage**: At least 2GB free space for generated artifacts

### Software Dependencies
- **Node.js** (v16 or higher) - for typosquatting simulations
- **Python 3** (v3.8 or higher) - for dependency confusion attacks
- **Ruby** (v2.7 or higher) - for supply chain attack simulations
- **jq** - for JSON processing in reports
- **Typosentinel Enterprise** - for detection testing (optional)

### Installation

#### macOS (using Homebrew)
```bash
brew install node python ruby jq
```

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install nodejs npm python3 python3-pip ruby jq
```

#### CentOS/RHEL
```bash
sudo yum install nodejs npm python3 python3-pip ruby jq
```

## Quick Start

### Run All Scenarios
```bash
# Make the orchestration script executable
chmod +x run-all-scenarios.sh

# Run all attack simulations
./run-all-scenarios.sh
```

### Run Individual Scenarios

#### Typosquatting Attacks
```bash
node typosquatting-attack.js
```

#### Dependency Confusion Attacks
```bash
python3 dependency-confusion-attack.py
```

#### Supply Chain Attacks
```bash
ruby supply-chain-attack.rb
```

## Configuration

The `test-config.json` file contains comprehensive configuration options:

### Registry Configuration
- **NPM**: JavaScript/Node.js packages
- **PyPI**: Python packages
- **Maven**: Java packages
- **NuGet**: .NET packages
- **RubyGems**: Ruby packages
- **Go Modules**: Go packages

### Attack Types
- **Typosquatting**: Character substitution, omission, insertion, transposition
- **Dependency Confusion**: Version bumping, metadata spoofing, delayed activation
- **Supply Chain**: Package takeover, dependency injection, build system compromise

### Evasion Techniques
- **Code Obfuscation**: Base64 encoding, hex encoding, dynamic evaluation
- **Anti-Analysis**: VM detection, debugger detection, sandbox evasion
- **Timing-Based**: Delayed activation, specific date triggers
- **Environment-Based**: Production-only activation, OS-specific behavior

## Generated Artifacts

Each simulation generates realistic attack artifacts:

### Package Files
- `package.json` (NPM)
- `requirements.txt` / `setup.py` (PyPI)
- `pom.xml` (Maven)
- `*.nuspec` (NuGet)
- `Gemfile` / `*.gemspec` (RubyGems)
- `go.mod` (Go)

### Malicious Payloads
- Credential harvesters
- Data exfiltrators
- Backdoor installers
- Cryptocurrency miners
- Keyloggers
- Network scanners

### Metadata
- Realistic package descriptions
- Fake maintainer information
- Legitimate-looking documentation
- Version histories
- Dependency lists

## Output and Reporting

### Report Structure
```
comprehensive-attack-report/
├── YYYYMMDD_HHMMSS/                   # Timestamped report directory
│   ├── comprehensive-attack-report.json  # Detailed JSON report
│   ├── attack-summary.md              # Human-readable summary
│   ├── detection-results.json         # Typosentinel detection results
│   ├── typosquatting/                 # Typosquatting artifacts
│   ├── dependency-confusion/          # Dependency confusion artifacts
│   ├── supply-chain/                  # Supply chain artifacts
│   ├── logs/                          # Execution logs
│   └── artifacts/                     # Generated package files
```

### Report Contents
- **Executive Summary**: High-level results and statistics
- **Attack Breakdown**: Detailed analysis of each attack type
- **Detection Analysis**: Results from Typosentinel scanning
- **Risk Assessment**: Risk scoring and categorization
- **Recommendations**: Security improvement suggestions
- **Technical Details**: Raw data and artifacts

## Security Considerations

### ⚠️ Important Warnings

1. **Isolated Environment**: Run these simulations only in isolated test environments
2. **No Real Uploads**: Scripts generate artifacts locally but do not upload to real registries
3. **Malicious Code**: Generated packages contain simulated malicious code for testing purposes
4. **Network Activity**: Some scripts may make network requests for realism
5. **File System Access**: Scripts create files and directories in the execution environment

### Safe Usage Guidelines

1. **Use Virtual Machines**: Run in disposable VMs or containers
2. **Network Isolation**: Use isolated networks or disable internet access
3. **Regular Cleanup**: Remove generated artifacts after testing
4. **Monitor Resources**: Watch for excessive CPU/memory usage
5. **Backup Data**: Ensure important data is backed up before testing

## Attack Scenarios Detail

### Typosquatting Attacks

**Objective**: Test detection of packages with names similar to popular legitimate packages

**Techniques**:
- Character substitution (o→0, i→l, m→rn)
- Character omission (express→expres)
- Character insertion (react→reactt)
- Character transposition (angular→angualr)
- Homograph attacks (Cyrillic characters)
- Subdomain confusion (@company→@companyy)

**Payloads**:
- Credential harvesting
- Data exfiltration
- Backdoor installation
- Cryptocurrency mining
- Botnet recruitment

### Dependency Confusion Attacks

**Objective**: Test detection of attacks targeting internal package names

**Techniques**:
- Version bumping (higher versions than internal packages)
- Metadata spoofing (copying legitimate package information)
- Delayed activation (time-based triggers)
- Environment detection (production-only activation)
- Code obfuscation (multiple encoding layers)

**Targets**:
- Internal authentication services
- Payment processing modules
- User management systems
- Logging utilities
- Configuration managers

### Supply Chain Attacks

**Objective**: Test detection of sophisticated supply chain compromises

**Techniques**:
- Package takeover simulation
- Dependency injection
- Build system compromise
- Transitive dependency poisoning
- Maintainer impersonation

**Advanced Features**:
- Multi-stage payloads
- Persistence mechanisms
- Anti-forensics techniques
- Command and control communication
- Lateral movement capabilities

## Customization

### Modifying Attack Parameters

Edit `test-config.json` to customize:

```json
{
  "attack_scenarios": {
    "typosquatting": {
      "target_count": 100,        // Number of malicious packages to generate
      "severity_levels": ["high"], // Focus on specific severity levels
      "techniques": {             // Enable/disable specific techniques
        "homograph_attack": {
          "enabled": true
        }
      }
    }
  }
}
```

### Adding New Registries

```json
{
  "registries": {
    "custom_registry": {
      "enabled": true,
      "registry_url": "https://custom.registry.com/",
      "test_packages": ["package1", "package2"],
      "attack_types": ["typosquatting"]
    }
  }
}
```

### Custom Payloads

Modify individual simulation scripts to add custom malicious payloads:

```javascript
// In typosquatting-attack.js
const customPayloads = {
  custom_backdoor: {
    description: "Custom backdoor implementation",
    code: "// Your custom malicious code here",
    stealth_level: "high"
  }
};
```

## Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Fix script permissions
chmod +x run-all-scenarios.sh

# Fix directory permissions
chmod -R 755 zero-day-scenarios/
```

#### Missing Dependencies
```bash
# Check Node.js version
node --version

# Check Python version
python3 --version

# Check Ruby version
ruby --version

# Install missing packages
npm install -g npm@latest
pip3 install --upgrade pip
gem update --system
```

#### Memory Issues
```bash
# Reduce target counts in test-config.json
# Monitor memory usage
top -p $(pgrep -f "attack")

# Clean up artifacts regularly
rm -rf comprehensive-attack-report/*/
```

#### Network Timeouts
```bash
# Increase timeout values in scripts
# Use local package mirrors
# Disable network-dependent features
```

### Debug Mode

Enable verbose logging:

```bash
# Set debug environment variable
export DEBUG=1
./run-all-scenarios.sh

# Or run individual scripts with debug
DEBUG=1 node typosquatting-attack.js
DEBUG=1 python3 dependency-confusion-attack.py
DEBUG=1 ruby supply-chain-attack.rb
```

## Integration with Typosentinel

### Automated Testing

The orchestration script automatically tests generated packages against Typosentinel if available:

```bash
# Ensure Typosentinel is in PATH or specify location
export TYPOSENTINEL_PATH="/path/to/typosentinel-enterprise"
./run-all-scenarios.sh
```

### Manual Testing

```bash
# Test individual packages
typosentinel-enterprise scan package.json

# Test entire directory
typosentinel-enterprise scan comprehensive-attack-report/20240120_143022/

# Generate detailed report
typosentinel-enterprise scan --format json --output results.json .
```

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
name: Zero-Day Attack Testing
on: [push, pull_request]

jobs:
  test-detection:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup dependencies
        run: |
          sudo apt-get update
          sudo apt-get install nodejs python3 ruby jq
      - name: Run attack simulations
        run: |
          cd tests/acme-enterprise/zero-day-scenarios
          chmod +x run-all-scenarios.sh
          ./run-all-scenarios.sh
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: attack-simulation-results
          path: tests/acme-enterprise/zero-day-scenarios/comprehensive-attack-report/
```

## Performance Optimization

### Parallel Execution

```bash
# Run scenarios in parallel
(
  node typosquatting-attack.js &
  python3 dependency-confusion-attack.py &
  ruby supply-chain-attack.rb &
  wait
)
```

### Resource Limits

```bash
# Limit memory usage
ulimit -m 2097152  # 2GB

# Limit CPU usage
cpulimit -l 50 ./run-all-scenarios.sh

# Limit file descriptors
ulimit -n 1024
```

### Cleanup Automation

```bash
# Automatic cleanup after 24 hours
find comprehensive-attack-report/ -type d -mtime +1 -exec rm -rf {} +

# Size-based cleanup (keep only latest 1GB)
du -sh comprehensive-attack-report/* | sort -hr | tail -n +10 | cut -f2 | xargs rm -rf
```

## Contributing

### Adding New Attack Scenarios

1. Create a new script file (e.g., `new-attack-type.py`)
2. Follow the existing pattern for artifact generation
3. Update `test-config.json` with new attack configuration
4. Modify `run-all-scenarios.sh` to include the new scenario
5. Add documentation to this README

### Improving Detection Evasion

1. Research new evasion techniques
2. Implement in existing scripts
3. Test against current Typosentinel version
4. Document new techniques in configuration
5. Update risk assessment criteria

### Reporting Issues

When reporting issues, include:

- Operating system and version
- Software dependency versions
- Complete error messages
- Steps to reproduce
- Generated log files
- System resource usage

## License

This testing framework is part of the Typosentinel project and is intended for security research and testing purposes only. Use responsibly and only in authorized environments.

## Disclaimer

⚠️ **WARNING**: These scripts generate simulated malicious packages for testing purposes. They should only be used in isolated, controlled environments for security testing. The authors are not responsible for any misuse of these tools or any damage caused by their use.

The generated packages contain code patterns similar to real malware but are designed for detection testing only. Do not use these tools for actual malicious purposes.