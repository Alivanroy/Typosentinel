package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommand(t *testing.T) {
	// Test that root command exists and has correct properties
	if rootCmd == nil {
		t.Error("Root command should not be nil")
	}
	
	// Test command name
	if rootCmd.Use != "typosentinel" {
		t.Errorf("Expected command name 'typosentinel', got '%s'", rootCmd.Use)
	}
	
	// Test that command has a description
	if rootCmd.Short == "" {
		t.Error("Root command should have a short description")
	}
}

func TestExecuteHelp(t *testing.T) {
	// Test that Execute function can handle help command
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()
	
	// Set args to help
	os.Args = []string{"typosentinel", "--help"}
	
	// Capture output
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"--help"})
	
	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("Execute with --help should not return error, got: %v", err)
	}
	
	output := buf.String()
	if len(output) == 0 {
		t.Error("Help output should not be empty")
	}
}

func TestScanCommand(t *testing.T) {
	// Test that scan command exists
	scanCmd := findCommand(rootCmd, "scan")
	if scanCmd == nil {
		t.Error("Scan command should exist")
	}
}

// Helper function to find a command by name
func findCommand(cmd *cobra.Command, name string) *cobra.Command {
	for _, subCmd := range cmd.Commands() {
		if subCmd.Name() == name {
			return subCmd
		}
	}
	return nil
}

func TestCommandFlags(t *testing.T) {
	// Test that basic flags exist
	if rootCmd.PersistentFlags().Lookup("config") == nil {
		t.Error("Config flag should exist")
	}
	
	if rootCmd.PersistentFlags().Lookup("verbose") == nil {
		t.Error("Verbose flag should exist")
	}
	
	if rootCmd.PersistentFlags().Lookup("debug") == nil {
		t.Error("Debug flag should exist")
	}
}

func TestExecute(t *testing.T) {
	// Test that Execute function exists and is callable
	// We can't test Execute() directly as it would run the actual command
	// Instead, we test that the function exists by checking if we can call it
	// without panicking in a controlled way
	
	defer func() {
		if r := recover(); r != nil {
			// It's okay if Execute panics due to missing arguments or config
			// We just want to ensure the function exists
			t.Logf("Execute panicked as expected: %v", r)
		}
	}()
	
	// Test that we can reference the Execute function
	// This will fail to compile if Execute doesn't exist
	_ = Execute
}