package scanner

import (
	"path/filepath"
	"strings"
)

// shouldSkipPath checks if a path should be skipped during scanning
func (s *Scanner) shouldSkipPath(path string) bool {
	// If RespectGitignore is not enabled, don't skip anything
	if s.config.Scanner == nil || !s.config.Scanner.RespectGitignore {
		return false
	}

	basename := filepath.Base(path)

	// Check scanner-configured skip patterns first
	if s.config.Scanner.SkipPatterns != nil {
		for _, pattern := range s.config.Scanner.SkipPatterns {
			// Basic prefix matching for performance
			if strings.HasPrefix(basename, pattern) {
				return true
			}
			// Also check exact match
			if matches, _ := filepath.Match(pattern, basename); matches {
				return true
			}
		}
	}

	// Common patterns to always skip (even if SkipPatterns is not configured)
	commonSkipPatterns := []string{
		"node_modules", ".git", "vendor", ".venv", "__pycache__",
		".tox", ".pytest_cache", // Python test/build
		"target",        // Java/Rust build
		"dist", "build", // Common build directories
		".terraform", ".gradle", // Infrastructure/build tools
		".svn", ".hg", ".bzr", // Other VCS
	}

	for _, pattern := range commonSkipPatterns {
		if basename == pattern || strings.HasPrefix(basename, pattern) {
			return true
		}
	}

	// Windows-specific: skip real-actions-, docker-test-, custom_test_workspace
	windowsSkipPrefixes := []string{
		"real-actions-",
		"docker-test-",
		"docker-realworld-",
		"docker-e2e-",
		"custom_test_workspace",
	}

	for _, prefix := range windowsSkipPrefixes {
		if strings.HasPrefix(basename, prefix) {
			return true
		}
	}

	return false
}
