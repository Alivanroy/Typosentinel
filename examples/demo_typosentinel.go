package main

import (
	"fmt"
	"strings"
)

// Simple demonstration of TypoSentinel's core typosquatting detection logic
func main() {
	fmt.Println("🔍 TypoSentinel Demo - Typosquatting Detection Examples")
	fmt.Println(strings.Repeat("=", 60))

	// Example 1: Common typosquatting patterns
	fmt.Println("\n📦 Example 1: Common Typosquatting Patterns")
	fmt.Println(strings.Repeat("-", 40))
	
	legitimatePackages := []string{
		"express",
		"lodash", 
		"react",
		"vue",
		"angular",
		"django",
		"flask",
		"requests",
		"numpy",
		"pandas",
	}

	typosquattingExamples := []string{
		"expres",     // missing 's'
		"lodahs",     // 's' instead of 'sh'
		"raact",      // double 'a'
		"veu",        // swapped letters
		"angualr",    // swapped letters
		"djnago",     // swapped letters
		"falsk",      // swapped letters
		"reqeusts",   // swapped letters
		"nmupy",      // swapped letters
		"pnadas",     // swapped letters
	}

	for i, legitimate := range legitimatePackages {
		typo := typosquattingExamples[i]
		similarity := calculateSimilarity(legitimate, typo)
		risk := assessRisk(similarity)
		
		fmt.Printf("✅ Legitimate: %-10s | ❌ Typosquatting: %-10s | Similarity: %.2f%% | Risk: %s\n", 
			legitimate, typo, similarity*100, risk)
	}

	// Example 2: Advanced detection techniques
	fmt.Println("\n🧠 Example 2: Advanced Detection Techniques")
	fmt.Println(strings.Repeat("-", 40))
	
	advancedExamples := map[string][]string{
		"Character Substitution": {"express", "3xpress", "expr3ss"},
		"Homoglyph Attack":      {"google", "g00gle", "goog1e"},
		"Subdomain Confusion":   {"github", "git-hub", "github-io"},
		"Hyphenation":          {"lodash", "lo-dash", "lodash-js"},
		"Pluralization":        {"request", "requests", "request-s"},
	}

	for technique, examples := range advancedExamples {
		fmt.Printf("\n🎯 %s:\n", technique)
		original := examples[0]
		for _, variant := range examples[1:] {
			similarity := calculateSimilarity(original, variant)
			risk := assessRisk(similarity)
			fmt.Printf("   %s → %s (Similarity: %.2f%%, Risk: %s)\n", 
				original, variant, similarity*100, risk)
		}
	}

	// Example 3: Real-world vulnerability scenarios
	fmt.Println("\n⚠️  Example 3: Real-world Vulnerability Scenarios")
	fmt.Println(strings.Repeat("-", 40))
	
	vulnerabilityScenarios := []struct {
		legitimate string
		malicious  string
		attack     string
		impact     string
	}{
		{"express", "expres", "Backdoor injection", "Remote code execution"},
		{"lodash", "lodahs", "Data exfiltration", "Sensitive data theft"},
		{"react", "raect", "Supply chain attack", "Compromised builds"},
		{"requests", "reqeusts", "Credential harvesting", "API key theft"},
	}

	for _, scenario := range vulnerabilityScenarios {
		similarity := calculateSimilarity(scenario.legitimate, scenario.malicious)
		fmt.Printf("🚨 %s → %s\n", scenario.legitimate, scenario.malicious)
		fmt.Printf("   Attack Type: %s\n", scenario.attack)
		fmt.Printf("   Potential Impact: %s\n", scenario.impact)
		fmt.Printf("   Detection Score: %.2f%%\n\n", similarity*100)
	}

	// Example 4: Package manager specific examples
	fmt.Println("📋 Example 4: Package Manager Specific Examples")
	fmt.Println(strings.Repeat("-", 40))
	
	packageManagers := map[string][]string{
		"npm (JavaScript)": {"express", "lodash", "react", "vue"},
		"PyPI (Python)":   {"django", "flask", "requests", "numpy"},
		"Maven (Java)":    {"spring-boot", "junit", "jackson", "slf4j"},
		"NuGet (.NET)":    {"newtonsoft.json", "entityframework", "autofac"},
		"Cargo (Rust)":    {"serde", "tokio", "clap", "regex"},
		"Go Modules":      {"gin", "mux", "logrus", "testify"},
	}

	for pm, packages := range packageManagers {
		fmt.Printf("\n🔧 %s:\n", pm)
		for _, pkg := range packages {
			// Generate a typosquatting example
			typo := generateTypo(pkg)
			similarity := calculateSimilarity(pkg, typo)
			risk := assessRisk(similarity)
			fmt.Printf("   ✅ %s → ❌ %s (Risk: %s)\n", pkg, typo, risk)
		}
	}

	fmt.Println("\n🎉 Demo completed! TypoSentinel helps protect against these and many more typosquatting attacks.")
	fmt.Println("💡 Tip: Always verify package names carefully and use dependency scanning tools!")
}

// calculateSimilarity calculates similarity between two strings using a simple algorithm
func calculateSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	
	// Simple Levenshtein-like similarity
	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}
	
	if maxLen == 0 {
		return 1.0
	}
	
	distance := levenshteinDistance(s1, s2)
	return 1.0 - float64(distance)/float64(maxLen)
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}

// assessRisk determines the risk level based on similarity score
func assessRisk(similarity float64) string {
	if similarity >= 0.9 {
		return "🔴 CRITICAL"
	} else if similarity >= 0.8 {
		return "🟠 HIGH"
	} else if similarity >= 0.7 {
		return "🟡 MEDIUM"
	} else if similarity >= 0.6 {
		return "🔵 LOW"
	}
	return "🟢 MINIMAL"
}

// generateTypo creates a simple typo for demonstration
func generateTypo(original string) string {
	if len(original) < 2 {
		return original + "x"
	}
	
	// Simple typo generation strategies
	strategies := []func(string) string{
		func(s string) string { return s[:len(s)-1] }, // remove last char
		func(s string) string { return s + "s" },      // add 's'
		func(s string) string { // swap two adjacent chars
			if len(s) >= 2 {
				runes := []rune(s)
				runes[0], runes[1] = runes[1], runes[0]
				return string(runes)
			}
			return s
		},
		func(s string) string { // replace a char
			return strings.Replace(s, "e", "3", 1)
		},
	}
	
	// Use a simple hash to pick a strategy consistently
	strategy := strategies[len(original)%len(strategies)]
	return strategy(original)
}