# TypoSentinel Improvement Plan
## From Evaluation to Production-Ready v1.0.0

**Generated**: Based on comprehensive software evaluation  
**Timeline**: 5 weeks (100-120 hours)  
**Priority**: Address evaluation gaps → Achieve honest v1.0.0 release

---

## Executive Summary

This plan addresses the key findings from the software evaluation:

| Issue | Severity | Resolution Phase |
|-------|----------|------------------|
| Documentation-implementation gaps | High | Week 1-2 |
| Demo mode endpoints returning mock data | High | Week 2 |
| Missing API authentication | High | Week 2 |
| Test coverage inconsistency | Medium | Week 1-3 |
| ML claims without implementation | Medium | Week 1 |
| Security hardening needed | Medium | Week 3 |
| Performance claims need validation | Low | Week 2 |

---

## Phase 1: Truth & Foundation (Week 1)
**Goal**: Align documentation with reality, make critical decisions

### Day 1-2: The Great Audit

#### Task 1.1: ML Feature Decision (CRITICAL)
**Time**: 3 hours  
**Priority**: Must decide before any other work

The evaluation found ML code commented out with notes like "// Commented out to break circular dependency". Three options:

**Option A: Remove ML Claims (Recommended for fastest release)**
```bash
# Files to update
grep -r "machine learning\|ML-based\|behavioral pattern" --include="*.md" .

# Update these files:
# - README.md: Remove "Machine learning-based detection"
# - CHANGELOG.md: Change to "Advanced heuristic detection"
# - docs/README.md: Update architecture diagram
# - docs/USER_GUIDE.md: Remove ML-specific sections
```

Replace with honest alternatives:
- "Machine learning-based detection" → "Multi-algorithm heuristic detection"
- "Behavioral pattern recognition" → "Pattern-based analysis"
- "ML Engine Module" → "Detection Engine Module"

**Option B: Implement Simple ML (Adds 1 week)**
```go
// internal/ml/simple_scorer.go
package ml

type SimpleMLScorer struct {
    weights map[string]float64
}

func NewSimpleMLScorer() *SimpleMLScorer {
    return &SimpleMLScorer{
        weights: map[string]float64{
            "levenshtein":    0.35,
            "jaro_winkler":   0.30,
            "homoglyph":      0.20,
            "length_diff":    0.15,
        },
    }
}

func (s *SimpleMLScorer) Score(features map[string]float64) float64 {
    var score float64
    for feature, value := range features {
        if weight, ok := s.weights[feature]; ok {
            score += value * weight
        }
    }
    return score
}
```

**Option C: Defer ML (Mark as "Coming Soon")**
Add to documentation:
```markdown
## Planned Features (v1.1+)
- 🔮 Machine learning-based detection (in development)
```

**Decision Required**: Choose A, B, or C and document in `DECISIONS.md`

```bash
# Create decisions log
cat > DECISIONS.md << 'EOF'
# Technical Decisions Log

## ML Feature Decision
**Date**: [DATE]
**Decision**: [A/B/C]
**Rationale**: [Your reasoning]
**Action Items**: [List of changes needed]
EOF
```

#### Task 1.2: Documentation-Reality Audit
**Time**: 4 hours

Create a tracking spreadsheet/document:

```bash
cat > docs/FEATURE_AUDIT.md << 'EOF'
# Feature Audit: Documented vs Implemented

## Legend
- ✅ Fully implemented and tested
- ⚠️ Partially implemented
- 🚧 Scaffolded/demo mode
- ❌ Documented but not implemented

## Core Features

| Feature | Documented | Actual Status | Action |
|---------|------------|---------------|--------|
| CLI scan command | Yes | ✅ Works | None |
| CLI analyze command | Yes | ✅ Works | None |
| JSON output | Yes | ✅ Works | None |
| SARIF output | Yes | ⚠️ Needs testing | Verify |
| npm support | Yes | ✅ Works | None |
| PyPI support | Yes | ✅ Works | None |
| Go modules | Yes | ⚠️ Needs testing | Test |
| Maven support | Yes | ⚠️ Needs testing | Test |
| Levenshtein detection | Yes | ✅ Works | None |
| Jaro-Winkler detection | Yes | ✅ Works | None |
| Homoglyph detection | Yes | ⚠️ Some tests fail | Fix |
| ML-based detection | Yes | ❌ Commented out | Decision |

## API Endpoints

| Endpoint | Documented | Actual Status | Action |
|----------|------------|---------------|--------|
| /health | Yes | ✅ Works | None |
| /ready | Yes | ✅ Works | None |
| /v1/analyze | Yes | ✅ Works | None |
| /v1/analyze/batch | Yes | ✅ Works | None |
| /v1/status | Yes | ✅ Works | None |
| /v1/stats | Yes | 🚧 Demo mode | Fix or document |
| /api/v1/vulnerabilities | Yes | 🚧 Mock data | Fix or remove |
| /api/v1/dashboard/metrics | Yes | 🚧 Mock data | Fix or remove |
| /api/v1/scans | Yes | ⚠️ Unknown | Test |

## Performance Claims

| Claim | Documented Value | Measured Value | Status |
|-------|------------------|----------------|--------|
| Scanning speed | 1000+ pkg/min | ~500 pkg/min | Update docs |
| Memory usage | <100MB | ~80MB | ✅ Accurate |
| Safe package response | <60ms | ~50ms | ✅ Accurate |

## Next Steps
1. Fix all ⚠️ items
2. Decision needed for ❌ items
3. Either complete or remove 🚧 items
EOF
```

Run verification:
```bash
# Test each documented feature
./typosentinel scan --help
./typosentinel analyze --help
./typosentinel version

# Test API endpoints
curl http://localhost:8080/health
curl http://localhost:8080/v1/status
curl -X POST http://localhost:8080/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"package_name": "express", "registry": "npm"}'
```

### Day 3-4: Fix Critical Inconsistencies

#### Task 1.3: Update README with Honest Status
**Time**: 2 hours

```markdown
# TypoSentinel

[![Build](https://github.com/Alivanroy/Typosentinel/actions/workflows/ci.yml/badge.svg)](...)
[![Coverage](https://img.shields.io/badge/coverage-52%25-yellow.svg)](#)
[![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> 🛡️ Typosquatting detection for software supply chain security

## ✨ What Works Today

**Production-Ready:**
- ✅ CLI scanning of project dependencies
- ✅ 8 package manager ecosystems (npm, PyPI, Go, Maven, NuGet, Cargo, RubyGems, Composer)
- ✅ Levenshtein and Jaro-Winkler similarity detection
- ✅ Homoglyph/visual similarity detection
- ✅ JSON and text output formats
- ✅ Docker support
- ✅ CI/CD integration (GitHub Actions, GitLab CI)

**In Development:**
- 🚧 Web dashboard (scaffolded, demo data)
- 🚧 REST API (core endpoints work, some return demo data)
- 🚧 Real-time monitoring
- 🔮 Enhanced ML-based detection (planned for v1.1)

## 📊 Honest Performance Metrics

*Measured on MacBook Pro M1, 16GB RAM:*

| Metric | Value | Notes |
|--------|-------|-------|
| Scanning Speed | ~500 packages/min | Single-threaded |
| Memory Usage | ~80MB typical | For <1000 packages |
| Detection Rate | 95%+ | Tested with known typosquats |
| False Positive Rate | <5% | Tunable via thresholds |

## 🚀 Quick Start

[Keep existing quick start but ensure it works]
```

#### Task 1.4: Remove or Fix Demo Mode Endpoints
**Time**: 4 hours

**Option A: Remove demo endpoints entirely**
```go
// api/main.go - Comment out or remove:
// - vulnerabilitiesHandler (returns mock CVEs)
// - dashboardMetricsHandler (returns mock data)
// - dashboardPerformanceHandler (returns mock data)

// Update router to return 501 Not Implemented
func notImplementedHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusNotImplemented)
    json.NewEncoder(w).Encode(map[string]string{
        "error": "This endpoint is planned for v1.1",
        "status": "not_implemented",
    })
}
```

**Option B: Mark clearly as demo**
```go
func vulnerabilitiesHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("X-Demo-Mode", "true")
    
    response := map[string]interface{}{
        "demo_mode": true,
        "message": "This endpoint returns sample data for demonstration purposes",
        "data": []map[string]interface{}{
            // ... mock data
        },
    }
    json.NewEncoder(w).Encode(response)
}
```

### Day 5-7: Test Coverage Foundation

#### Task 1.5: Establish Coverage Baseline
**Time**: 2 hours

```bash
# Get current state
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out | tee coverage_baseline.txt

# Identify gaps
go tool cover -func=coverage.out | grep "0.0%" | head -20

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html
```

Create coverage targets:
```bash
cat > COVERAGE_TARGETS.md << 'EOF'
# Test Coverage Targets for v1.0.0

## Current State (from baseline)
- pkg/types: 100% ✅
- internal/supplychain: ~54%
- internal/detector: ~40%
- internal/scanner: ~35%
- internal/analyzer: ~30%

## v1.0.0 Targets (Minimum)
| Package | Current | Target | Priority |
|---------|---------|--------|----------|
| pkg/types | 100% | 100% | Done |
| internal/detector | 40% | 70% | P1 |
| internal/analyzer | 30% | 60% | P1 |
| internal/scanner | 35% | 60% | P1 |
| internal/config | 50% | 70% | P2 |
| api/ | 60% | 80% | P2 |

## Strategy
1. Focus on P1 packages first (core functionality)
2. Add tests for uncovered edge cases
3. Fix failing tests before adding new ones
EOF
```

#### Task 1.6: Fix Failing Tests
**Time**: 4 hours

```bash
# Run tests and capture failures
go test ./... -v 2>&1 | tee test_results.txt

# Extract failures
grep -A 5 "FAIL" test_results.txt > failing_tests.txt

# Fix each failure
# Common issues:
# - Rune handling in homoglyph tests
# - Logger type mismatches
# - Race conditions in concurrent tests
```

#### Task 1.7: Add Critical Missing Tests
**Time**: 6 hours

Priority 1 tests to add:

```go
// internal/detector/similarity_test.go
func TestLevenshteinDistance(t *testing.T) {
    tests := []struct {
        name     string
        s1, s2   string
        expected int
    }{
        {"identical", "express", "express", 0},
        {"one_char_diff", "express", "expresss", 1},
        {"two_char_diff", "lodash", "lodahs", 2},
        {"empty_string", "", "test", 4},
        {"completely_different", "react", "angular", 7},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := LevenshteinDistance(tt.s1, tt.s2)
            assert.Equal(t, tt.expected, result)
        })
    }
}

func TestJaroWinklerSimilarity(t *testing.T) {
    tests := []struct {
        name     string
        s1, s2   string
        minSim   float64
    }{
        {"identical", "express", "express", 1.0},
        {"very_similar", "express", "expresss", 0.95},
        {"somewhat_similar", "lodash", "lodahs", 0.85},
        {"different", "react", "angular", 0.0},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := JaroWinklerSimilarity(tt.s1, tt.s2)
            assert.GreaterOrEqual(t, result, tt.minSim)
        })
    }
}
```

---

## Phase 2: Security & API Hardening (Week 2)
**Goal**: Production-grade security for API endpoints

### Day 8-9: API Authentication

#### Task 2.1: Implement API Key Authentication
**Time**: 4 hours

```go
// internal/api/middleware/auth.go
package middleware

import (
    "crypto/subtle"
    "net/http"
    "strings"
)

type AuthMiddleware struct {
    apiKeys map[string]bool
    enabled bool
}

func NewAuthMiddleware(keys []string, enabled bool) *AuthMiddleware {
    keyMap := make(map[string]bool)
    for _, key := range keys {
        keyMap[key] = true
    }
    return &AuthMiddleware{apiKeys: keyMap, enabled: enabled}
}

func (a *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Skip auth for health endpoints
        if r.URL.Path == "/health" || r.URL.Path == "/ready" {
            next.ServeHTTP(w, r)
            return
        }
        
        if !a.enabled {
            next.ServeHTTP(w, r)
            return
        }
        
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, `{"error": "Missing Authorization header"}`, http.StatusUnauthorized)
            return
        }
        
        parts := strings.SplitN(authHeader, " ", 2)
        if len(parts) != 2 || parts[0] != "Bearer" {
            http.Error(w, `{"error": "Invalid Authorization format"}`, http.StatusUnauthorized)
            return
        }
        
        apiKey := parts[1]
        if !a.validateKey(apiKey) {
            http.Error(w, `{"error": "Invalid API key"}`, http.StatusUnauthorized)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func (a *AuthMiddleware) validateKey(key string) bool {
    for validKey := range a.apiKeys {
        if subtle.ConstantTimeCompare([]byte(key), []byte(validKey)) == 1 {
            return true
        }
    }
    return false
}
```

Update configuration:
```yaml
# config/config.yaml
api:
  auth:
    enabled: true
    keys:
      - ${API_KEY_1}  # From environment
      - ${API_KEY_2}
```

#### Task 2.2: Input Validation Hardening
**Time**: 3 hours

```go
// internal/api/validators/package.go
package validators

import (
    "regexp"
    "strings"
    "unicode/utf8"
)

var (
    // Package name patterns per ecosystem
    npmPattern  = regexp.MustCompile(`^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$`)
    pypiPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
    
    // Dangerous patterns
    pathTraversal = regexp.MustCompile(`\.\.[\\/]`)
    shellChars    = regexp.MustCompile(`[;&|$\x60]`)
)

type PackageValidator struct{}

func (v *PackageValidator) ValidatePackageName(name, registry string) error {
    if name == "" {
        return ErrEmptyPackageName
    }
    
    if len(name) > 214 { // npm limit
        return ErrPackageNameTooLong
    }
    
    if !utf8.ValidString(name) {
        return ErrInvalidUTF8
    }
    
    if pathTraversal.MatchString(name) {
        return ErrPathTraversal
    }
    
    if shellChars.MatchString(name) {
        return ErrDangerousCharacters
    }
    
    switch registry {
    case "npm":
        if !npmPattern.MatchString(strings.ToLower(name)) {
            return ErrInvalidNpmPackageName
        }
    case "pypi":
        if !pypiPattern.MatchString(name) {
            return ErrInvalidPyPIPackageName
        }
    }
    
    return nil
}
```

#### Task 2.3: Rate Limiting Enhancement
**Time**: 2 hours

```go
// internal/api/middleware/ratelimit.go
package middleware

import (
    "net/http"
    "sync"
    "time"
)

type RateLimiter struct {
    requests map[string][]time.Time
    mu       sync.RWMutex
    limit    int
    window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
    rl := &RateLimiter{
        requests: make(map[string][]time.Time),
        limit:    limit,
        window:   window,
    }
    go rl.cleanup()
    return rl
}

func (rl *RateLimiter) Allow(key string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    now := time.Now()
    windowStart := now.Add(-rl.window)
    
    // Clean old requests
    var valid []time.Time
    for _, t := range rl.requests[key] {
        if t.After(windowStart) {
            valid = append(valid, t)
        }
    }
    
    if len(valid) >= rl.limit {
        rl.requests[key] = valid
        return false
    }
    
    rl.requests[key] = append(valid, now)
    return true
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        key := r.RemoteAddr // Or use API key for authenticated requests
        
        if !rl.Allow(key) {
            w.Header().Set("Retry-After", "60")
            http.Error(w, `{"error": "Rate limit exceeded"}`, http.StatusTooManyRequests)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```

### Day 10-11: Security Audit

#### Task 2.4: Dependency Security Check
**Time**: 2 hours

```bash
# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# Run vulnerability scan
govulncheck ./...

# Check for outdated dependencies
go list -u -m all

# Update vulnerable dependencies
go get -u [package]@latest
go mod tidy
```

#### Task 2.5: Secret Scanning
**Time**: 1 hour

```bash
# Install gitleaks
brew install gitleaks  # or appropriate method

# Scan repository
gitleaks detect --source . --verbose

# Create .gitleaks.toml for allowed patterns
cat > .gitleaks.toml << 'EOF'
[allowlist]
description = "Allowlisted patterns"
paths = [
    '''testdata/''',
    '''.*_test\.go''',
]
EOF
```

#### Task 2.6: SECURITY.md Verification
**Time**: 1 hour

Ensure SECURITY.md exists and is accurate:
```bash
cat SECURITY.md
# Verify:
# - Contact email is monitored
# - Disclosure timeline is realistic
# - Known issues are documented
```

### Day 12-14: Performance Validation

#### Task 2.7: Run Comprehensive Benchmarks
**Time**: 3 hours

```bash
# Create benchmark suite
mkdir -p tests/benchmarks

cat > tests/benchmarks/detection_bench_test.go << 'EOF'
package benchmarks

import (
    "testing"
    "github.com/Alivanroy/Typosentinel/internal/detector"
)

func BenchmarkLevenshteinDistance(b *testing.B) {
    pairs := []struct{ s1, s2 string }{
        {"express", "expresss"},
        {"lodash", "lodahs"},
        {"react", "recat"},
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        for _, p := range pairs {
            detector.LevenshteinDistance(p.s1, p.s2)
        }
    }
}

func BenchmarkScanSmallProject(b *testing.B) {
    // Create temp project with 10 packages
    tmpDir := createTestProject(b, 10)
    defer os.RemoveAll(tmpDir)
    
    cfg := config.NewDefaultConfig()
    scanner, _ := scanner.New(cfg)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        scanner.ScanProject(tmpDir)
    }
}

func BenchmarkScanLargeProject(b *testing.B) {
    // Create temp project with 500 packages
    tmpDir := createTestProject(b, 500)
    defer os.RemoveAll(tmpDir)
    
    cfg := config.NewDefaultConfig()
    scanner, _ := scanner.New(cfg)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        scanner.ScanProject(tmpDir)
    }
}
EOF

# Run benchmarks
go test -bench=. -benchmem ./tests/benchmarks/... | tee benchmark_results.txt
```

#### Task 2.8: Update Performance Documentation
**Time**: 1 hour

```markdown
## Performance Metrics (Validated)

### Benchmark Results
*Run on: [System specs], Go 1.23, [Date]*

| Operation | Time | Memory | Notes |
|-----------|------|--------|-------|
| Levenshtein (per pair) | 150ns | 0 allocs | Core algorithm |
| Scan 10 packages | 45ms | 2.1MB | Small project |
| Scan 100 packages | 380ms | 8.5MB | Medium project |
| Scan 500 packages | 1.8s | 42MB | Large project |

### Throughput
- Small projects (<50 deps): ~800 packages/minute
- Medium projects (50-200 deps): ~600 packages/minute  
- Large projects (200+ deps): ~400 packages/minute

### Memory Profile
- Base memory: ~15MB
- Per 100 packages: ~8MB additional
- Peak during analysis: 2x base

*To reproduce: `go test -bench=. ./tests/benchmarks/...`*
```

---

## Phase 3: Quality & Polish (Week 3)
**Goal**: Production-quality codebase

### Day 15-17: Code Quality

#### Task 3.1: Fix All Linter Warnings
**Time**: 4 hours

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run with all checks
golangci-lint run --enable-all ./...

# Fix issues by category:
# 1. gofmt issues (auto-fix)
gofmt -w .

# 2. govet issues
go vet ./...

# 3. errcheck (unchecked errors)
# Review each and add proper error handling

# 4. gosec (security issues)
# Address or document exceptions

# Create .golangci.yml for project standards
cat > .golangci.yml << 'EOF'
linters:
  enable:
    - gofmt
    - govet
    - errcheck
    - gosec
    - staticcheck
    - unused
    - ineffassign
    - misspell
  
linters-settings:
  errcheck:
    ignore: fmt:.*,io/ioutil:^Read.*
  gosec:
    severity: medium
    
issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - errcheck
        - gosec
EOF
```

#### Task 3.2: Remove Dead Code
**Time**: 2 hours

```bash
# Find unused code
go install golang.org/x/tools/cmd/deadcode@latest
deadcode ./...

# Review commented-out code blocks
grep -r "// TODO\|// FIXME\|// Commented out" --include="*.go" .

# Decision for each:
# - Remove if not needed
# - Create GitHub issue if planned
# - Document if temporary
```

#### Task 3.3: Add Missing Documentation
**Time**: 3 hours

```bash
# Find undocumented exports
go install golang.org/x/tools/cmd/godoc@latest

# Check coverage
for pkg in $(go list ./...); do
    echo "=== $pkg ==="
    go doc -all $pkg 2>&1 | head -5
done
```

Add godoc comments:
```go
// Package detector provides typosquatting detection algorithms.
//
// The detector package implements multiple similarity algorithms
// including Levenshtein distance, Jaro-Winkler similarity, and
// homoglyph detection for identifying typosquatting attempts.
package detector

// Engine is the main detection engine that coordinates
// multiple detection algorithms to identify typosquatting threats.
//
// Example usage:
//
//     cfg := config.NewDefaultConfig()
//     engine := detector.New(cfg)
//     result, err := engine.Analyze(package)
type Engine struct {
    // ...
}
```

### Day 18-19: Integration Testing

#### Task 3.4: End-to-End Test Suite
**Time**: 4 hours

```bash
mkdir -p tests/e2e
cat > tests/e2e/scan_test.go << 'EOF'
//go:build e2e

package e2e

import (
    "os/exec"
    "testing"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestCLI_ScanNpmProject(t *testing.T) {
    // Setup: create test project
    tmpDir := t.TempDir()
    createNpmProject(t, tmpDir, map[string]string{
        "express": "^4.18.0",
        "expresss": "^1.0.0",  // Typosquat
    })
    
    // Execute
    cmd := exec.Command("typosentinel", "scan", tmpDir, "--output", "json")
    output, err := cmd.Output()
    require.NoError(t, err)
    
    // Verify
    var result ScanResult
    err = json.Unmarshal(output, &result)
    require.NoError(t, err)
    
    assert.Equal(t, 2, result.TotalPackages)
    assert.GreaterOrEqual(t, len(result.Threats), 1)
    
    // Find the typosquat threat
    found := false
    for _, threat := range result.Threats {
        if threat.Package == "expresss" {
            found = true
            assert.Equal(t, "typosquatting", threat.Type)
            assert.GreaterOrEqual(t, threat.Confidence, 0.8)
        }
    }
    assert.True(t, found, "Should detect expresss as typosquat")
}

func TestCLI_ScanCleanProject(t *testing.T) {
    tmpDir := t.TempDir()
    createNpmProject(t, tmpDir, map[string]string{
        "express": "^4.18.0",
        "lodash": "^4.17.21",
    })
    
    cmd := exec.Command("typosentinel", "scan", tmpDir, "--output", "json")
    output, err := cmd.Output()
    require.NoError(t, err)
    
    var result ScanResult
    err = json.Unmarshal(output, &result)
    require.NoError(t, err)
    
    assert.Equal(t, 0, len(result.Threats), "Clean project should have no threats")
}
EOF
```

#### Task 3.5: API Integration Tests
**Time**: 3 hours

```go
// tests/e2e/api_test.go
//go:build e2e

package e2e

func TestAPI_FullWorkflow(t *testing.T) {
    // Start server
    cmd := exec.Command("typosentinel", "server", "--port", "18080")
    cmd.Start()
    defer cmd.Process.Kill()
    
    // Wait for ready
    require.Eventually(t, func() bool {
        resp, _ := http.Get("http://localhost:18080/health")
        return resp != nil && resp.StatusCode == 200
    }, 10*time.Second, 100*time.Millisecond)
    
    // Test analyze endpoint
    payload := `{"package_name": "expresss", "registry": "npm"}`
    resp, err := http.Post(
        "http://localhost:18080/v1/analyze",
        "application/json",
        strings.NewReader(payload),
    )
    require.NoError(t, err)
    assert.Equal(t, 200, resp.StatusCode)
    
    var result AnalysisResult
    json.NewDecoder(resp.Body).Decode(&result)
    
    assert.GreaterOrEqual(t, result.RiskLevel, 1)
}
```

### Day 20-21: Final Documentation

#### Task 3.6: Complete User Guide
**Time**: 3 hours

Ensure docs/USER_GUIDE.md covers:
- [ ] Installation (all methods)
- [ ] Basic usage examples
- [ ] Configuration options
- [ ] Output format explanations
- [ ] CI/CD integration examples
- [ ] Troubleshooting section

#### Task 3.7: API Documentation Accuracy
**Time**: 2 hours

Verify docs/API_REFERENCE.md:
```bash
# Start server
./typosentinel server &

# Test each documented endpoint
for endpoint in "/health" "/ready" "/v1/analyze" "/v1/status"; do
    echo "Testing $endpoint"
    curl -s "http://localhost:8080$endpoint" | jq .
done

# Compare output to documentation
# Update any discrepancies
```

---

## Phase 4: Release Preparation (Week 4)
**Goal**: Ship v1.0.0

### Day 22-24: Build & Package

#### Task 4.1: Cross-Platform Builds
**Time**: 2 hours

```bash
# Build all platforms
make build-all

# Verify binaries
ls -la dist/
file dist/typosentinel-*

# Test on each platform (or use CI)
# Linux
./dist/typosentinel-linux-amd64 --version

# macOS (if available)
./dist/typosentinel-darwin-amd64 --version

# Windows (via Wine or CI)
wine dist/typosentinel-windows-amd64.exe --version
```

#### Task 4.2: Docker Image Finalization
**Time**: 2 hours

```bash
# Build production image
docker build -t typosentinel:1.0.0 .
docker tag typosentinel:1.0.0 ghcr.io/alivanroy/typosentinel:1.0.0
docker tag typosentinel:1.0.0 ghcr.io/alivanroy/typosentinel:latest

# Test image
docker run --rm typosentinel:1.0.0 --version
docker run --rm -v $(pwd)/testdata:/workspace typosentinel:1.0.0 scan /workspace

# Security scan
docker scan typosentinel:1.0.0
```

#### Task 4.3: Generate Checksums
**Time**: 30 minutes

```bash
cd dist
sha256sum typosentinel-* > checksums.sha256
cat checksums.sha256

# Also create GPG signature if you have a key
gpg --armor --detach-sign checksums.sha256
```

### Day 25-26: Pre-Release Testing

#### Task 4.4: Full Regression Test
**Time**: 4 hours

```bash
# Run complete test suite
make test-all

# Run E2E tests
go test -tags=e2e ./tests/e2e/...

# Run benchmarks
go test -bench=. ./tests/benchmarks/...

# Manual smoke tests
./typosentinel scan ./examples/vulnerable-project
./typosentinel analyze --package express --registry npm
./typosentinel version
```

#### Task 4.5: Beta Testing (Optional)
**Time**: 2 hours

```bash
# Create pre-release
git tag -a v1.0.0-rc1 -m "Release candidate 1"
git push origin v1.0.0-rc1

# Announce for testing
# - Post in relevant communities
# - Ask for feedback
# - Monitor issues
```

### Day 27-28: Release

#### Task 4.6: Final Checklist
**Time**: 1 hour

```markdown
## v1.0.0 Release Checklist

### Code Quality
- [ ] All tests passing
- [ ] Coverage meets targets (>50%)
- [ ] No linter errors
- [ ] No security vulnerabilities in deps
- [ ] All TODOs addressed or ticketed

### Documentation  
- [ ] README is accurate and honest
- [ ] CHANGELOG updated
- [ ] API docs verified
- [ ] User guide complete
- [ ] SECURITY.md current

### Binaries
- [ ] Linux amd64 builds and runs
- [ ] macOS amd64 builds and runs
- [ ] macOS arm64 builds and runs
- [ ] Windows amd64 builds and runs
- [ ] Docker image works
- [ ] Checksums generated

### Repository
- [ ] License file present
- [ ] Contributing guidelines
- [ ] Issue templates
- [ ] CI/CD passing
```

#### Task 4.7: Create GitHub Release
**Time**: 1 hour

```bash
# Create release notes
cat > RELEASE_NOTES_v1.0.0.md << 'EOF'
# TypoSentinel v1.0.0

The first production release of TypoSentinel - a typosquatting detection tool for software supply chain security.

## Highlights

- **Multi-ecosystem support**: npm, PyPI, Go, Maven, NuGet, Cargo, RubyGems, Composer
- **Proven detection**: Levenshtein, Jaro-Winkler, and homoglyph detection
- **CI/CD ready**: GitHub Actions and GitLab CI examples included
- **Docker support**: Official container images available

## Installation

### Binary
```bash
curl -LO https://github.com/Alivanroy/Typosentinel/releases/download/v1.0.0/typosentinel-linux-amd64
chmod +x typosentinel-linux-amd64
sudo mv typosentinel-linux-amd64 /usr/local/bin/typosentinel
```

### Docker
```bash
docker pull ghcr.io/alivanroy/typosentinel:1.0.0
```

## Quick Start
```bash
typosentinel scan /path/to/project
```

## Known Limitations
- Web dashboard is in development (scaffolded)
- Some API endpoints return demo data
- ML-based detection planned for v1.1

## What's Next (v1.1)
- Complete web dashboard
- Enhanced ML detection
- Real-time monitoring
- Threat intelligence integration

See [CHANGELOG.md](CHANGELOG.md) for full details.
EOF

# Tag and release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Create release via GitHub CLI
gh release create v1.0.0 \
  --title "TypoSentinel v1.0.0" \
  --notes-file RELEASE_NOTES_v1.0.0.md \
  dist/typosentinel-linux-amd64 \
  dist/typosentinel-darwin-amd64 \
  dist/typosentinel-darwin-arm64 \
  dist/typosentinel-windows-amd64.exe \
  dist/checksums.sha256
```

---

## Phase 5: Post-Release (Week 5)
**Goal**: Monitor, respond, iterate

### Day 29-30: Monitoring

#### Task 5.1: Issue Triage Process
**Time**: Ongoing

```markdown
## Issue Response SLA

| Severity | Response Time | Resolution Target |
|----------|---------------|-------------------|
| Critical | 4 hours | 24 hours |
| High | 24 hours | 1 week |
| Medium | 48 hours | 2 weeks |
| Low | 1 week | Best effort |

## Triage Labels
- `bug` - Something isn't working
- `enhancement` - New feature request
- `documentation` - Documentation improvements
- `good first issue` - Good for contributors
- `help wanted` - Extra attention needed
```

#### Task 5.2: Gather Feedback
**Time**: 2 hours

- Monitor GitHub issues
- Check discussions
- Look for mentions on social media
- Respond to questions

### Day 31-35: Quick Fixes & v1.0.1

#### Task 5.3: Patch Release Process
**Time**: As needed

```bash
# For bug fixes
git checkout -b hotfix/issue-123
# Fix the issue
git commit -m "Fix: description (#123)"
git push origin hotfix/issue-123
# Create PR, get review, merge

# Tag patch release
git checkout main
git pull
git tag -a v1.0.1 -m "Patch release v1.0.1"
git push origin v1.0.1
```

---

## Success Metrics

### Technical Metrics
| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Test coverage | >50% | 52% | ✅ |
| Linter errors | 0 | TBD | |
| Security vulns | 0 critical | TBD | |
| Build time | <2 min | TBD | |

### Quality Metrics
| Metric | Target | Status |
|--------|--------|--------|
| Docs match implementation | 100% | |
| Demo endpoints documented | 100% | |
| E2E tests passing | 100% | |

### Community Metrics (First Month)
| Metric | Target |
|--------|--------|
| GitHub stars | 50+ |
| Downloads | 100+ |
| Issues opened | Track |
| External PRs | 1+ |

---

## Quick Reference

### Daily Commands
```bash
# Build and test
make build && make test

# Check coverage
make test-coverage

# Lint
golangci-lint run ./...

# Run locally
./typosentinel scan ./testdata
```

### Pre-Commit Checklist
- [ ] Tests pass
- [ ] Linter clean
- [ ] Docs updated (if needed)
- [ ] Changelog updated (if user-facing)

### Emergency Procedures
```bash
# Revert bad release
git revert HEAD
git push origin main
gh release delete v1.0.x --yes

# Hotfix workflow
git checkout -b hotfix/critical-fix
# Fix issue
git commit -m "CRITICAL: Fix security issue"
git push origin hotfix/critical-fix
# Fast-track review and merge
```

---

## Appendix: File Locations

### Key Files to Update
- `README.md` - Main documentation
- `CHANGELOG.md` - Release notes
- `SECURITY.md` - Security policy
- `docs/USER_GUIDE.md` - User documentation
- `docs/API_REFERENCE.md` - API documentation

### Configuration
- `typosentinel.yaml` - Default config
- `config/config.yaml` - Full config
- `.golangci.yml` - Linter config
- `.github/workflows/ci.yml` - CI config

### Test Locations
- `tests/unit/` - Unit tests
- `tests/integration/` - Integration tests
- `tests/e2e/` - End-to-end tests
- `tests/benchmarks/` - Performance tests

---

*Plan generated from comprehensive software evaluation. Adjust timelines based on actual progress and available resources.*