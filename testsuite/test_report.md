# Typosentinel Real-World Test Report

**Generated:** 2025-07-05 18:59:22
**Test Duration:** 0:00:00.328268
**Overall Result:** ❌ FAIL

## Executive Summary

- **Total Tests:** 15
- **Passed:** 7
- **Failed:** 8
- **Pass Rate:** 46.7%

## Accuracy Metrics

- **Threat Detection Rate:** 100.0%
- **False Positive Rate:** 100.0%
- **Precision:** 0.857
- **Recall:** 1.000
- **F1 Score:** 0.923

## Performance Metrics

- **Total Packages Tested:** 15
- **Packages per Second:** 36.14
- **Average Processing Time:** 28ms
- **95th Percentile Time:** 113ms
- **99th Percentile Time:** 113ms

## Test Categories

### Threat Typosquatting

- **Tests:** 1
- **Passed:** 1
- **Pass Rate:** 100.0%

- ✅ `npm_lodahs` - Score: 0.956 (Expected: 0.800)

### Legitimate Package

- **Tests:** 1
- **Passed:** 0
- **Pass Rate:** 0.0%

- ❌ `npm_lodash` - Score: 0.956 (Expected: 0.300)

### Typosquatting Pattern

- **Tests:** 5
- **Passed:** 5
- **Pass Rate:** 100.0%

- ✅ `typosquat_lodahs_vs_lodash` - Score: 0.956 (Expected: 0.800)
- ✅ `typosquat_recat_vs_react` - Score: 0.943 (Expected: 0.800)
- ✅ `typosquat_reqeusts_vs_requests` - Score: 0.956 (Expected: 0.800)
- ✅ `typosquat_expresss_vs_express` - Score: 0.956 (Expected: 0.800)
- ✅ `typosquat_nmupy_vs_numpy` - Score: 0.942 (Expected: 0.800)

### Package Scan

- **Tests:** 6
- **Passed:** 0
- **Pass Rate:** 0.0%

- ❌ `npm_lodash` - Score: 0.956 (Expected: 0.300)
- ❌ `npm_react` - Score: 0.956 (Expected: 0.300)
- ❌ `npm_express` - Score: 0.956 (Expected: 0.300)
- ❌ `pypi_requests` - Score: 0.956 (Expected: 0.300)
- ❌ `pypi_numpy` - Score: 0.956 (Expected: 0.300)
- ❌ `pypi_flask` - Score: 0.956 (Expected: 0.300)

### Performance

- **Tests:** 1
- **Passed:** 1
- **Pass Rate:** 100.0%

- ✅ `batch_performance` - Score: 52.892 (Expected: 5.000)

### Project Scanning

- **Tests:** 1
- **Passed:** 0
- **Pass Rate:** 0.0%

- ❌ `npm_project_scan` - Score: 0.000 (Expected: 1.000)

## Failed Tests

### npm_lodash

- **Category:** legitimate_package
- **Score:** 0.956 (Expected: 0.300)
- **Processing Time:** 13ms
- **Error:** 

### npm_lodash

- **Category:** package_scan
- **Score:** 0.956 (Expected: 0.300)
- **Processing Time:** 25ms
- **Error:** 

### npm_react

- **Category:** package_scan
- **Score:** 0.956 (Expected: 0.300)
- **Processing Time:** 13ms
- **Error:** 

### npm_express

- **Category:** package_scan
- **Score:** 0.956 (Expected: 0.300)
- **Processing Time:** 21ms
- **Error:** 

### pypi_requests

- **Category:** package_scan
- **Score:** 0.956 (Expected: 0.300)
- **Processing Time:** 14ms
- **Error:** 

### pypi_numpy

- **Category:** package_scan
- **Score:** 0.956 (Expected: 0.300)
- **Processing Time:** 16ms
- **Error:** 

### pypi_flask

- **Category:** package_scan
- **Score:** 0.956 (Expected: 0.300)
- **Processing Time:** 15ms
- **Error:** 

### npm_project_scan

- **Category:** project_scanning
- **Score:** 0.000 (Expected: 1.000)
- **Processing Time:** 8ms
- **Error:** Error: unknown flag: --project-path
Usage:
  typosentinel scan [package-name] [flags]

Flags:
  -c, --config string          Configuration file path
      --fail-fast              Stop on first critical finding
  -f, --format string          Output format (json, yaml, text, table, compact, detailed, summary) (default "json")
  -h, --help                   help for scan
  -l, --local string           Scan local package file or directory
      --no-color               Disable colored output
      --only-engines strings   Only run specified analysis engines
  -o, --output string          Output file path
  -p, --parallel int           Number of parallel scans (default 1)
      --pkg-version string     Package version to scan (default "latest")
      --progress               Show progress during scan (default true)
  -q, --quiet                  Suppress non-essential output
  -r, --registry string        Package registry (npm, pypi, go, etc.) (default "npm")
      --save-report            Save detailed report to file
      --skip-engines strings   Analysis engines to skip
  -t, --timeout string         Scan timeout duration (default "5m")

Global Flags:
      --debug               enable debug mode
      --debug-mode string   set debug mode (basic, verbose, trace, performance, security)
      --log-format string   set log format (text, json)
      --log-level string    set log level (trace, verbose, debug, info, warn, error, fatal)
      --log-output string   set log output (stdout, stderr, file path)
      --trace               enable trace mode (most verbose)
      --verbose             enable verbose logging



## Recommendations

- ⚠️ Reduce false positive rate - review legitimate package scoring
- ❌ Address issues before production deployment
