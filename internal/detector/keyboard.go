package detector

import (
	"math"
	"strings"
	"unicode"
)

// keyboardProximitySimilarity analyzes keyboard layout proximity
func (etd *EnhancedTyposquattingDetector) keyboardProximitySimilarity(s1, s2 string) float64 {
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Use QWERTY layout (first in the list)
	if len(etd.keyboardLayouts) == 0 {
		return 0.0
	}
	layout := etd.keyboardLayouts[0]

	// Calculate proximity-aware edit distance
	proximityScore := etd.proximityEditDistance(s1, s2, layout)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))

	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - (proximityScore / maxLen)
}

// proximityEditDistance calculates edit distance considering keyboard proximity
func (etd *EnhancedTyposquattingDetector) proximityEditDistance(s1, s2 string, layout KeyboardLayout) float64 {
	runes1 := []rune(s1)
	runes2 := []rune(s2)
	m, n := len(runes1), len(runes2)

	// Create DP matrix
	dp := make([][]float64, m+1)
	for i := range dp {
		dp[i] = make([]float64, n+1)
	}

	// Initialize base cases
	for i := 0; i <= m; i++ {
		dp[i][0] = float64(i)
	}
	for j := 0; j <= n; j++ {
		dp[0][j] = float64(j)
	}

	// Fill DP matrix
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if runes1[i-1] == runes2[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				// Calculate proximity cost for substitution
				proximityCost := etd.getProximityCost(runes1[i-1], runes2[j-1], layout)

				dp[i][j] = math.Min(
					math.Min(
						dp[i-1][j]+1.0,  // deletion
						dp[i][j-1]+1.0), // insertion
					dp[i-1][j-1]+proximityCost) // substitution with proximity cost
			}
		}
	}

	return dp[m][n]
}

// getProximityCost returns the cost of substituting one character for another based on keyboard proximity
func (etd *EnhancedTyposquattingDetector) getProximityCost(c1, c2 rune, layout KeyboardLayout) float64 {
	c1Lower := unicode.ToLower(c1)
	c2Lower := unicode.ToLower(c2)

	// Check if characters are adjacent on keyboard
	if adjacent, ok := layout.Layout[c1Lower]; ok {
		for _, adj := range adjacent {
			if adj == c2Lower {
				return 0.3 // Low cost for adjacent keys
			}
		}
	}

	// Check if characters are in the same row
	for _, row := range layout.Rows {
		c1InRow := strings.ContainsRune(row, c1Lower)
		c2InRow := strings.ContainsRune(row, c2Lower)
		if c1InRow && c2InRow {
			return 0.6 // Medium cost for same row
		}
	}

	return 1.0 // Full cost for non-adjacent keys
}
