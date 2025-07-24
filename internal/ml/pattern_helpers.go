package ml

import (
	"regexp"
	"strings"
	"time"
)

// Helper functions for enhanced pattern detection

// countConsecutiveConsonants counts the maximum number of consecutive consonants in a string
func countConsecutiveConsonants(s string) int {
	s = strings.ToLower(s)
	consonants := "bcdfghjklmnpqrstvwxyz"
	max := 0
	current := 0
	
	for _, c := range s {
		if strings.ContainsRune(consonants, c) {
			current++
			if current > max {
				max = current
			}
		} else {
			current = 0
		}
	}
	
	return max
}

// countConsecutiveVowels counts the maximum number of consecutive vowels in a string
func countConsecutiveVowels(s string) int {
	s = strings.ToLower(s)
	vowels := "aeiou"
	max := 0
	current := 0
	
	for _, c := range s {
		if strings.ContainsRune(vowels, c) {
			current++
			if current > max {
				max = current
			}
		} else {
			current = 0
		}
	}
	
	return max
}

// countConsecutiveDigits counts the maximum number of consecutive digits in a string
func countConsecutiveDigits(s string) int {
	digits := "0123456789"
	max := 0
	current := 0
	
	for _, c := range s {
		if strings.ContainsRune(digits, c) {
			current++
			if current > max {
				max = current
			}
		} else {
			current = 0
		}
	}
	
	return max
}

// hasHomoglyphs checks if a string contains homoglyphs (characters that look similar)
func hasHomoglyphs(s string) bool {
	homoglyphs := map[rune][]rune{
		'o': {'0', 'O'},
		'0': {'o', 'O'},
		'l': {'1', 'I', 'i'},
		'1': {'l', 'I', 'i'},
		'I': {'1', 'l', 'i'},
		'i': {'1', 'l', 'I'},
		'e': {'3'},
		'3': {'e'},
		'a': {'@'},
		'@': {'a'},
		's': {'5', '$'},
		'5': {'s'},
		'$': {'s'},
		'b': {'6'},
		'6': {'b'},
		'g': {'9'},
		'9': {'g'},
	}
	
	for i := 0; i < len(s)-1; i++ {
		if substitutes, exists := homoglyphs[rune(s[i])]; exists {
			for _, substitute := range substitutes {
				if i > 0 && rune(s[i-1]) == substitute {
					return true
				}
				if i < len(s)-1 && rune(s[i+1]) == substitute {
					return true
				}
			}
		}
	}
	
	return false
}

// hasMixedCase checks if a string has mixed case in an unusual pattern
func hasMixedCase(s string) bool {
	if len(s) < 3 {
		return false
	}
	
	upperCount := 0
	lowerCount := 0
	alternating := 0
	
	for i, c := range s {
		if c >= 'A' && c <= 'Z' {
			upperCount++
			if i > 0 && s[i-1] >= 'a' && s[i-1] <= 'z' {
				alternating++
			}
		} else if c >= 'a' && c <= 'z' {
			lowerCount++
			if i > 0 && s[i-1] >= 'A' && s[i-1] <= 'Z' {
				alternating++
			}
		}
	}
	
	// Unusual if mixed case with alternating pattern or random capitalization
	return (upperCount > 0 && lowerCount > 0) && 
	       (alternating >= 2 || (upperCount < lowerCount && upperCount > 0 && upperCount < len(s)/3))
}

// hasUnusualCharacters checks if a string contains unusual characters
func hasUnusualCharacters(s string) bool {
	unusualChars := "~`!@#$%^&*()_+={}[]|\\:;\"'<>,.?/"
	count := 0
	
	for _, c := range s {
		if strings.ContainsRune(unusualChars, c) {
			count++
		}
	}
	
	return count > 1 || (count > 0 && len(s) < 6)
}

// hasSuspiciousPattern checks if a string has suspicious patterns
func hasSuspiciousPattern(s string) bool {
	// Check for repeating patterns
	if len(s) >= 6 {
		for i := 2; i <= len(s)/2; i++ {
			pattern := s[:i]
			if strings.Count(s, pattern) > 1 && len(pattern) > 1 {
				return true
			}
		}
	}
	
	// Check for alternating characters
	if len(s) >= 4 {
		alternating := true
		for i := 2; i < len(s); i++ {
			if s[i] != s[i%2] {
				alternating = false
				break
			}
		}
		if alternating {
			return true
		}
	}
	
	return false
}

// hasCommonPrefix checks if a string has a common package prefix
func hasCommonPrefix(s string) bool {
	commonPrefixes := []string{
		"node-", "react-", "vue-", "angular-", "jquery-", "lodash-",
		"express-", "webpack-", "babel-", "eslint-", "prettier-", "typescript-",
		"python-", "django-", "flask-", "numpy-", "pandas-", "tensorflow-",
		"pytorch-", "scikit-", "go-", "gin-", "echo-", "fiber-", "mux-",
	}
	
	for _, prefix := range commonPrefixes {
		if strings.HasPrefix(strings.ToLower(s), prefix) {
			return true
		}
	}
	
	return false
}

// hasCommonSuffix checks if a string has a common package suffix
func hasCommonSuffix(s string) bool {
	commonSuffixes := []string{
		"-js", "-ts", "-node", "-react", "-vue", "-angular", "-jquery",
		"-utils", "-helper", "-lib", "-sdk", "-api", "-client", "-server",
		"-ui", "-core", "-common", "-shared", "-util", "-tools", "-plugin",
		"-extension", "-module", "-package", "-wrapper", "-bundle", "-kit",
	}
	
	for _, suffix := range commonSuffixes {
		if strings.HasSuffix(strings.ToLower(s), suffix) {
			return true
		}
	}
	
	return false
}

// hasRepeatedCharacters checks if a string has unusual repeated characters
func hasRepeatedCharacters(s string) bool {
	s = strings.ToLower(s)
	
	for i := 0; i < len(s)-2; i++ {
		if s[i] == s[i+1] && s[i] == s[i+2] {
			return true
		}
	}
	
	return false
}

// hasKeyboardPattern checks if a string contains keyboard patterns
func hasKeyboardPattern(s string) bool {
	keyboardPatterns := []string{
		"qwert", "asdfg", "zxcvb", "yuiop", "hjkl", "nm",
		"12345", "67890", "poiuy", "lkjhg", "mnbvc",
	}
	
	s = strings.ToLower(s)
	for _, pattern := range keyboardPatterns {
		if strings.Contains(s, pattern) {
			return true
		}
		// Check reverse pattern too
		reverse := reverseString(pattern)
		if strings.Contains(s, reverse) {
			return true
		}
	}
	
	return false
}

// reverseString reverses a string
func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// isUnusualVersion checks if a version string is unusual
func isUnusualVersion(version string) bool {
	// Check for very short versions
	if len(version) < 3 {
		return true
	}
	
	// Check for versions with unusual characters
	unusualChars := "~`!@#$%^&*()_+={}[]|\\:;\"'<>?/"
	for _, c := range version {
		if strings.ContainsRune(unusualChars, c) {
			return true
		}
	}
	
	// Check for versions with unusual format
	validVersionPattern := regexp.MustCompile(`^\d+(\.\d+)*(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$`)
	return !validVersionPattern.MatchString(version)
}

// isVeryNewVersion checks if a version is very new (0.x.y or 1.0.0)
func isVeryNewVersion(version string) bool {
	return strings.HasPrefix(version, "0.") || version == "1.0.0"
}

// hasSuspiciousTerms checks if a string contains suspicious terms
func hasSuspiciousTerms(s string) bool {
	s = strings.ToLower(s)
	suspiciousTerms := []string{
		"hack", "crack", "exploit", "backdoor", "malware", "virus",
		"trojan", "keylog", "steal", "phish", "scam", "fake",
		"unofficial", "mirror", "clone", "copy", "duplicate",
		"password", "credential", "token", "auth", "login", "admin",
		"root", "sudo", "shell", "command", "exec", "run", "eval",
		"crypto", "wallet", "bitcoin", "ethereum", "nft", "token",
		"free", "cracked", "nulled", "patched", "keygen", "serial",
		"bypass", "inject", "payload", "rootkit", "ransomware", "spyware",
	}
	
	for _, term := range suspiciousTerms {
		if strings.Contains(s, term) {
			return true
		}
	}
	
	return false
}

// hasURLs checks if a string contains URLs
func hasURLs(s string) bool {
	urlPattern := regexp.MustCompile(`https?://[^\s]+`)
	return urlPattern.MatchString(s)
}

// hasRandomPattern checks if a string appears to be random
func hasRandomPattern(s string) bool {
	// High entropy and unusual character distribution
	return calculateEntropy(s) > 4.0 && len(s) > 5
}

// hasUnusualCharacterCombinations checks for unusual character combinations
func hasUnusualCharacterCombinations(s string) bool {
	unusualCombinations := []string{
		"0o", "o0", "1l", "l1", "1i", "i1", "5s", "s5",
		"rn", "vv", "cl", "nn", "m", "gq", "vy",
	}
	
	s = strings.ToLower(s)
	for _, combo := range unusualCombinations {
		if strings.Contains(s, combo) {
			return true
		}
	}
	
	return false
}

// hasDeceptivePrefix checks for deceptive prefixes
func hasDeceptivePrefix(s string) bool {
	s = strings.ToLower(s)
	deceptivePrefixes := []string{
		"official-", "original-", "real-", "true-", "genuine-",
		"auth-", "secure-", "safe-", "trusted-", "verified-",
	}
	
	for _, prefix := range deceptivePrefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	
	return false
}

// hasDeceptiveSuffix checks for deceptive suffixes
func hasDeceptiveSuffix(s string) bool {
	s = strings.ToLower(s)
	deceptiveSuffixes := []string{
		"-official", "-original", "-real", "-true", "-genuine",
		"-auth", "-secure", "-safe", "-trusted", "-verified",
	}
	
	for _, suffix := range deceptiveSuffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	
	return false
}

// hasSuspiciousDependencies checks for suspicious dependencies
func hasSuspiciousDependencies(deps map[string]string) bool {
	for dep := range deps {
		if hasSuspiciousTerms(dep) || hasUnusualCharacters(dep) {
			return true
		}
	}
	
	return false
}

// hasUnusualDependencyVersions checks for unusual dependency versions
func hasUnusualDependencyVersions(deps map[string]string) bool {
	for _, version := range deps {
		if isUnusualVersion(version) {
			return true
		}
	}
	
	return false
}

// calculatePackageAgeDays calculates the age of a package in days
func calculatePackageAgeDays(createdAt time.Time) int {
	if createdAt.IsZero() {
		return 0
	}
	
	return int(time.Since(createdAt).Hours() / 24)
}

// calculateDaysSinceLastUpdate calculates days since the last update
func calculateDaysSinceLastUpdate(updatedAt time.Time) int {
	if updatedAt.IsZero() {
		return 0
	}
	
	return int(time.Since(updatedAt).Hours() / 24)
}

// calculateUpdateFrequency calculates the update frequency
func calculateUpdateFrequency(updateHistory []time.Time) float64 {
	if len(updateHistory) < 2 {
		return 0.0
	}
	
	// Sort the update history (assuming it's already sorted)
	totalDays := 0.0
	for i := 1; i < len(updateHistory); i++ {
		duration := updateHistory[i].Sub(updateHistory[i-1])
		totalDays += duration.Hours() / 24
	}
	
	// Average days between updates
	avgDays := totalDays / float64(len(updateHistory)-1)
	if avgDays == 0 {
		return 0.0
	}
	
	// Return updates per month
	return 30.0 / avgDays
}