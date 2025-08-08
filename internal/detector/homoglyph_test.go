package detector

import (
	"testing"
)

func TestIsHomoglyphVariant(t *testing.T) {
	hd := NewHomoglyphDetector()

	tests := []struct {
		name     string
		s1       string
		s2       string
		expected bool
	}{
		{
			name:     "should return true for homoglyph variants",
			s1:       "apple",
			s2:       "appӏe", // using Cyrillic 'ӏ'
			expected: true,
		},
		{
			name:     "should return false for non-homoglyph variants",
			s1:       "apple",
			s2:       "banana",
			expected: false,
		},
		{
			name:     "should return false for strings of different lengths",
			s1:       "apple",
			s2:       "apples",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hd.isHomoglyphVariant(tt.s1, tt.s2); got != tt.expected {
				t.Errorf("isHomoglyphVariant() = %v, want %v", got, tt.expected)
			}
		})
	}
}
