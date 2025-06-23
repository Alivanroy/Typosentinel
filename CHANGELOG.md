# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive benchmark suite for performance testing
- Performance testing documentation in user guide and API docs
- Memory usage profiling and optimization benchmarks
- Concurrent scanning performance tests
- Throughput and stress testing capabilities
- Custom benchmark configuration options
- Detailed performance metrics collection

### Fixed
- **Critical**: Resolved analyzer variable shadowing issues in benchmark functions
- Fixed `analyzer.ScanOptions` type recognition problems
- Corrected function naming consistency in benchmark suite
- Resolved build compilation errors in `internal/benchmark` package
- Updated benchmark function references from old names to new standardized names
- **Major**: Fixed all import paths throughout the codebase from `typosentinel/` to `github.com/Alivanroy/Typosentinel/`
- Resolved build failures caused by incorrect module import paths
- Updated all Go files to use the correct GitHub repository import paths

### Changed
- Renamed benchmark functions for better organization:
  - `BenchmarkConcurrentScans` → `BenchmarkConcurrentScans2`
  - `BenchmarkMemoryUsage` → `BenchmarkMemoryUsage2`
  - `createTestPackage` → `createTestPackage2`
  - `createLargeTestPackage` → `createLargeTestPackage2`
- Improved variable naming to avoid package import shadowing
- Enhanced benchmark suite architecture for better maintainability

### Improved
- Enhanced documentation with performance testing sections
- Added comprehensive benchmark usage examples
- Improved code quality and maintainability
- Better error handling in benchmark functions
- Optimized memory allocation patterns in benchmarks

### Documentation
- Updated README.md with performance benchmarking features
- Enhanced PROJECT_DOCUMENTATION.md with recent improvements
- Added detailed benchmarking section to API_DOCUMENTATION.md
- Expanded USER_GUIDE.md with performance testing guide
- Added code quality and maintenance documentation

## [Previous Versions]

*Previous changelog entries would be documented here as the project evolves.*