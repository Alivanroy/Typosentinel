package detector

import (
	"math"
	"strings"
	"testing"
)

func TestGenerateThreatID(t *testing.T) {
	id1 := generateThreatID()
	id2 := generateThreatID()

	// Should generate unique IDs
	if id1 == id2 {
		t.Error("Expected unique threat IDs")
	}

	// Should be hex string of reasonable length
	if len(id1) == 0 {
		t.Error("Threat ID should not be empty")
	}

	if len(id1) != 32 { // 16 bytes = 32 hex characters
		t.Errorf("Expected 32 character hex string, got %d", len(id1))
	}

	// Should only contain hex characters
	for _, char := range id1 {
		if !strings.ContainsRune("0123456789abcdef", char) {
			t.Errorf("Threat ID contains invalid character: %c", char)
		}
	}
}

func TestMinInt(t *testing.T) {
	tests := []struct {
		name     string
		vals     []int
		expected int
	}{
		{"single value", []int{5}, 5},
		{"two values", []int{3, 7}, 3},
		{"multiple values", []int{10, 5, 8, 2, 9}, 2},
		{"negative values", []int{-1, -5, 0, 3}, -5},
		{"mixed values", []int{0, -10, 5, -3}, -10},
		{"empty slice", []int{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := minInt(tt.vals...)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestMinInt_EdgeCases(t *testing.T) {
	// Test with very large numbers
	result := minInt(math.MaxInt32, math.MinInt32)
	if result != math.MinInt32 {
		t.Errorf("Expected %d, got %d", math.MinInt32, result)
	}

	// Test with identical values
	result = minInt(42, 42, 42)
	if result != 42 {
		t.Errorf("Expected 42, got %d", result)
	}

	// Test with one very large negative number
	result = minInt(-999999, -1, -100)
	if result != -999999 {
		t.Errorf("Expected -999999, got %d", result)
	}
}