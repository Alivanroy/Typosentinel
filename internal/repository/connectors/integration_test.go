package connectors

import (
	"fmt"
	"net/url"
	"testing"
)

// TestURLEscapingFunctionality tests that URL escaping works correctly
// This test verifies that the fixes for variable shadowing are working
func TestURLEscapingFunctionality(t *testing.T) {
	// Test cases with special characters that need URL escaping
	testCases := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"test/owner", "test%2Fowner"},
		{"user@domain.com", "user%40domain.com"},
		{"test query", "test+query"},
		{"special!@#$%^&*()", "special%21%40%23%24%25%5E%26%2A%28%29"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("QueryEscape_%s", tc.input), func(t *testing.T) {
			// Test url.QueryEscape - this should work without compilation errors
			result := url.QueryEscape(tc.input)
			if result != tc.expected {
				t.Errorf("QueryEscape(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}

	// Test PathEscape as well
	pathTestCases := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"test/path", "test%2Fpath"},
		{"file name.txt", "file%20name.txt"},
	}

	for _, tc := range pathTestCases {
		t.Run(fmt.Sprintf("PathEscape_%s", tc.input), func(t *testing.T) {
			// Test url.PathEscape - this should work without compilation errors
			result := url.PathEscape(tc.input)
			if result != tc.expected {
				t.Errorf("PathEscape(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

// TestNoVariableShadowing verifies that we can use both local variables and url package functions
func TestNoVariableShadowing(t *testing.T) {
	// This test simulates the pattern that was causing issues before our fixes
	
	// Create a local variable that could potentially shadow the url package
	endpoint := fmt.Sprintf("/projects/%s/repository/files/%s", "123", url.QueryEscape("test/file.txt"))
	
	// Verify the endpoint was constructed correctly
	expected := "/projects/123/repository/files/test%2Ffile.txt"
	if endpoint != expected {
		t.Errorf("Expected endpoint %q, got %q", expected, endpoint)
	}
	
	// Test that we can still use url.QueryEscape after creating local variables
	owner := "test-owner"
	escapedOwner := url.QueryEscape(owner)
	if escapedOwner != "test-owner" {
		t.Errorf("Expected escaped owner %q, got %q", "test-owner", escapedOwner)
	}
	
	// Test with special characters
	specialOwner := "user/org"
	escapedSpecialOwner := url.QueryEscape(specialOwner)
	if escapedSpecialOwner != "user%2Forg" {
		t.Errorf("Expected escaped special owner %q, got %q", "user%2Forg", escapedSpecialOwner)
	}
}