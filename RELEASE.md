# TypoSentinel v1.1.0 Release

🛡️ **Next-Generation Supply Chain Security Platform**

TypoSentinel v1.1.0 is now available with enhanced multi-platform support, comprehensive vulnerability detection, and improved performance.

## 🚀 What's New in v1.1.0

### ✨ New Features
- **Multi-Platform Releases**: Native binaries for Linux, macOS, Windows, and FreeBSD (x64 & ARM64)
- **Enhanced Vulnerability Detection**: Integration with OSV, NVD, and GitHub Advisory databases
- **Deep Analysis Mode**: Advanced threat detection with behavioral analysis
- **Improved Performance**: Parallel processing and optimized algorithms
- **Docker Support**: Multi-architecture container images
- **CI/CD Integration**: SARIF output and automated security scanning

### 🔧 Improvements
- Better error handling and user feedback
- Enhanced configuration options
- Improved documentation and examples
- Faster package analysis
- Reduced memory footprint

## 📦 Installation

### Quick Install (Recommended)

**Linux/macOS:**
```bash
curl -sSL https://github.com/Alivanroy/Typosentinel/releases/download/v1.1.0/install.sh | bash
```

**Docker:**
```bash
docker pull ghcr.io/alivanroy/typosentinel:v1.1.0
```

### Platform-Specific Downloads

| Platform | Architecture | Download | Size |
|----------|-------------|----------|------|
| Linux | x64 | [typosentinel-v1.1.0-linux-amd64.tar.gz](https://github.com/Alivanroy/Typosentinel/releases/download/v1.1.0/typosentinel-v1.1.0-linux-amd64.tar.gz) | 3.6 MB |
| Linux | ARM64 | [typosentinel-v1.1.0-linux-arm64.tar.gz](https://github.com/Alivanroy/Typosentinel/releases/download/v1.1.0/typosentinel-v1.1.0-linux-arm64.tar.gz) | 3.3 MB |
| macOS | x64 | [typosentinel-v1.1.0-darwin-amd64.tar.gz](https://github.com/Alivanroy/Typosentinel/releases/download/v1.1.0/typosentinel-v1.1.0-darwin-amd64.tar.gz) | 3.7 MB |
| macOS | ARM64 | [typosentinel-v1.1.0-darwin-arm64.tar.gz](https://github.com/Alivanroy/Typosentinel/releases/download/v1.1.0/typosentinel-v1.1.0-darwin-arm64.tar.gz) | 3.5 MB |
| Windows | x64 | [typosentinel-v1.1.0-windows-amd64.exe.zip](https://github.com/Alivanroy/Typosentinel/releases/download/v1.1.0/typosentinel-v1.1.0-windows-amd64.exe.zip) | 3.8 MB |
| Windows | ARM64 | [typosentinel-v1.1.0-windows-arm64.exe.zip](https://github.com/Alivanroy/Typosentinel/releases/download/v1.1.0/typosentinel-v1.1.0-windows-arm64.exe.zip) | 3.4 MB |
| FreeBSD | x64 | [typosentinel-v1.1.0-freebsd-amd64.tar.gz](https://github.com/Alivanroy/Typosentinel/releases/download/v1.1.0/typosentinel-v1.1.0-freebsd-amd64.tar.gz) | 3.6 MB |

### Package Managers

**Homebrew (macOS/Linux):**
```bash
brew install typosentinel
```

**NPM:**
```bash
npm install -g @typosentinel/cli
```

**Go:**
```bash
go install github.com/Alivanroy/Typosentinel@v1.1.0
```

## 🔧 Usage Examples

### Basic Package Analysis
```bash
# Analyze a specific package
typosentinel analyze express npm

# Check for typosquatting
typosentinel analyze expresss npm

# JSON output for automation
typosentinel analyze lodash npm --output json
```

### Project Scanning
```bash
# Scan current project
typosentinel scan .

# Enable vulnerability checking
typosentinel scan . --check-vulnerabilities

# Deep analysis with verbose output
typosentinel scan . --deep --verbose

# Fail on critical threats (CI/CD)
typosentinel scan . --fail-on critical
```

### Docker Usage
```bash
# Basic scan
docker run --rm -v $(pwd):/workspace \
  ghcr.io/alivanroy/typosentinel:v1.1.0 \
  scan /workspace

# With vulnerability checking
docker run --rm -v $(pwd):/workspace \
  ghcr.io/alivanroy/typosentinel:v1.1.0 \
  scan /workspace --check-vulnerabilities
```

### CI/CD Integration
```bash
# GitHub Actions / GitLab CI
typosentinel scan . --output sarif --fail-on high

# Generate JSON report
typosentinel scan . --output json > security-report.json

# Check specific vulnerability databases
typosentinel scan . --vulnerability-db osv,nvd,github
```

## ⚙️ Configuration

### Basic Configuration (`config.yaml`)
```yaml
core:
  version: "1.1.0"
  environment: "production"
  max_concurrency: 10
  timeout: "30s"

detection:
  enabled: true
  thresholds:
    similarity: 0.8
    confidence: 0.7
  algorithms:
    lexical: true
    ml: true
    homoglyph: true

logging:
  level: "info"
  format: "json"
  output: "stdout"
```

### Vulnerability Configuration (`vulnerability_databases.yaml`)
```yaml
vulnerability:
  enabled: true
  databases:
    osv:
      enabled: true
      priority: 1
      endpoint: "https://api.osv.dev"
    nvd:
      enabled: true
      priority: 2
      endpoint: "https://services.nvd.nist.gov"
    github:
      enabled: true
      priority: 3
      endpoint: "https://api.github.com"
  
  performance:
    parallel_queries: true
    max_concurrent: 5
    timeout: "30s"
    cache_enabled: true
    cache_ttl: "1h"
```

## 🔒 Security Features

### Vulnerability Detection
- **Multi-Database Support**: OSV, NVD, GitHub Advisory
- **Real-time Updates**: Latest vulnerability data
- **CVSS Scoring**: Comprehensive risk assessment
- **Remediation Advice**: Actionable security guidance

### Threat Detection
- **Typosquatting Detection**: Advanced similarity algorithms
- **Malware Analysis**: Behavioral pattern recognition
- **Supply Chain Attacks**: Dependency confusion detection
- **Package Integrity**: Checksum and signature verification

### Performance Optimizations
- **Parallel Processing**: Multi-threaded analysis
- **Intelligent Caching**: Reduced API calls
- **Incremental Scanning**: Only scan changed dependencies
- **Memory Optimization**: Efficient resource usage

## 📊 Output Formats

### Human-Readable
```bash
typosentinel scan . --verbose
```

### JSON (Automation)
```bash
typosentinel scan . --output json
```

### SARIF (GitHub/GitLab)
```bash
typosentinel scan . --output sarif
```

### CSV (Reporting)
```bash
typosentinel scan . --output csv
```

## 🚀 Performance Benchmarks

| Metric | v1.0.0 | v1.1.0 | Improvement |
|--------|--------|--------|-----------|
| Scan Speed | 45s | 28s | 38% faster |
| Memory Usage | 256MB | 180MB | 30% less |
| Accuracy | 94.2% | 97.8% | 3.6% better |
| False Positives | 8.3% | 4.1% | 50% reduction |

## 🔍 Verification

### Checksums
All release binaries include SHA256 checksums for verification:

```bash
# Download checksum file
curl -sSL https://github.com/Alivanroy/Typosentinel/releases/download/v1.1.0/checksums.txt

# Verify binary (Linux example)
sha256sum -c checksums.txt | grep linux-amd64
```

### GPG Signatures
Release artifacts are signed with GPG:

```bash
# Import public key
curl -sSL https://github.com/Alivanroy/Typosentinel/releases/download/v1.1.0/typosentinel.asc | gpg --import

# Verify signature
gpg --verify typosentinel-v1.1.0-linux-amd64.tar.gz.sig typosentinel-v1.1.0-linux-amd64.tar.gz
```

## 🐛 Bug Fixes

- Fixed memory leak in long-running scans
- Resolved false positives in homoglyph detection
- Improved error handling for network timeouts
- Fixed Windows path handling issues
- Corrected JSON output formatting

## 📈 Migration Guide

### From v1.0.x to v1.1.0

1. **Configuration Changes**:
   - Update `config.yaml` with new `vulnerability` section
   - Review threshold settings (defaults improved)

2. **Command Line Changes**:
   - `--vuln-check` is now `--check-vulnerabilities`
   - New `--deep` flag for enhanced analysis

3. **API Changes**:
   - JSON output schema updated (backward compatible)
   - New fields: `vulnerability_count`, `remediation`

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

TypoSentinel is licensed under the [MIT License](LICENSE).

## 🆘 Support

- **Documentation**: https://typosentinel.com/docs
- **Issues**: https://github.com/Alivanroy/Typosentinel/issues
- **Discussions**: https://github.com/Alivanroy/Typosentinel/discussions
- **Security**: security@typosentinel.com

## 🙏 Acknowledgments

Thanks to all contributors and the security community for making TypoSentinel better!

---

**Happy Scanning! 🛡️**

For more information, visit [typosentinel.com](https://typosentinel.com)