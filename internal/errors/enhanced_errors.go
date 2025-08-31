package errors

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// ErrorCategory represents different types of errors
type ErrorCategory string

const (
	CategoryConfiguration ErrorCategory = "configuration"
	CategoryNetwork       ErrorCategory = "network"
	CategoryPermission    ErrorCategory = "permission"
	CategoryDependency    ErrorCategory = "dependency"
	CategoryValidation    ErrorCategory = "validation"
	CategoryInternal      ErrorCategory = "internal"
	CategoryUsage         ErrorCategory = "usage"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	ErrorSeverityLow      ErrorSeverity = "low"
	ErrorSeverityMedium   ErrorSeverity = "medium"
	ErrorSeverityHigh     ErrorSeverity = "high"
	ErrorSeverityCritical ErrorSeverity = "critical"
)

// EnhancedError provides user-friendly error messages with context and suggestions
type EnhancedError struct {
	// Core error information
	Code     string
	Message  string
	Category ErrorCategory
	Severity ErrorSeverity
	Cause    error
	Context  map[string]interface{}

	// User-friendly information
	UserMessage   string
	Explanation   string
	Suggestions   []string
	Documentation string
	Examples      []string

	// Technical details
	StackTrace string
	Timestamp  string
	Component  string
}

// Error implements the error interface
func (e *EnhancedError) Error() string {
	return e.Message
}

// Unwrap returns the underlying error
func (e *EnhancedError) Unwrap() error {
	return e.Cause
}

// ErrorFormatter handles formatting of enhanced errors for different outputs
type ErrorFormatter struct {
	colorEnabled bool
	verboseMode  bool
}

// NewErrorFormatter creates a new error formatter
func NewErrorFormatter(colorEnabled, verboseMode bool) *ErrorFormatter {
	return &ErrorFormatter{
		colorEnabled: colorEnabled,
		verboseMode:  verboseMode,
	}
}

// Format formats an enhanced error for display
func (f *ErrorFormatter) Format(err *EnhancedError) string {
	var output strings.Builder

	// Header with severity indicator
	severityColor := f.getSeverityColor(err.Severity)
	if f.colorEnabled {
		output.WriteString(severityColor.Sprint(f.getSeverityIcon(err.Severity)))
		output.WriteString(" ")
		output.WriteString(color.New(color.Bold).Sprint(err.UserMessage))
	} else {
		output.WriteString(fmt.Sprintf("[%s] %s", strings.ToUpper(string(err.Severity)), err.UserMessage))
	}
	output.WriteString("\n")

	// Explanation
	if err.Explanation != "" {
		output.WriteString("\n")
		if f.colorEnabled {
			output.WriteString(color.New(color.FgWhite).Sprint("💡 What happened:"))
		} else {
			output.WriteString("What happened:")
		}
		output.WriteString("\n")
		output.WriteString(f.wrapText(err.Explanation, 2))
		output.WriteString("\n")
	}

	// Suggestions
	if len(err.Suggestions) > 0 {
		output.WriteString("\n")
		if f.colorEnabled {
			output.WriteString(color.New(color.FgGreen).Sprint("🔧 How to fix:"))
		} else {
			output.WriteString("How to fix:")
		}
		output.WriteString("\n")
		for i, suggestion := range err.Suggestions {
			output.WriteString(fmt.Sprintf("  %d. %s\n", i+1, suggestion))
		}
	}

	// Examples
	if len(err.Examples) > 0 && f.verboseMode {
		output.WriteString("\n")
		if f.colorEnabled {
			output.WriteString(color.New(color.FgCyan).Sprint("📝 Examples:"))
		} else {
			output.WriteString("Examples:")
		}
		output.WriteString("\n")
		for _, example := range err.Examples {
			output.WriteString(f.wrapText(example, 2))
			output.WriteString("\n")
		}
	}

	// Documentation link
	if err.Documentation != "" {
		output.WriteString("\n")
		if f.colorEnabled {
			output.WriteString(color.New(color.FgBlue).Sprint("📚 Learn more: "))
			output.WriteString(color.New(color.Underline).Sprint(err.Documentation))
		} else {
			output.WriteString(fmt.Sprintf("Learn more: %s", err.Documentation))
		}
		output.WriteString("\n")
	}

	// Technical details (verbose mode only)
	if f.verboseMode {
		output.WriteString("\n")
		if f.colorEnabled {
			output.WriteString(color.New(color.FgYellow).Sprint("🔍 Technical Details:"))
		} else {
			output.WriteString("Technical Details:")
		}
		output.WriteString("\n")
		output.WriteString(fmt.Sprintf("  Error Code: %s\n", err.Code))
		output.WriteString(fmt.Sprintf("  Category: %s\n", err.Category))
		output.WriteString(fmt.Sprintf("  Component: %s\n", err.Component))
		if err.Cause != nil {
			output.WriteString(fmt.Sprintf("  Original Error: %s\n", err.Cause.Error()))
		}
		if len(err.Context) > 0 {
			output.WriteString("  Context:\n")
			for key, value := range err.Context {
				output.WriteString(fmt.Sprintf("    %s: %v\n", key, value))
			}
		}
	}

	return output.String()
}

// getSeverityColor returns the color for a given severity
func (f *ErrorFormatter) getSeverityColor(severity ErrorSeverity) *color.Color {
	switch severity {
	case ErrorSeverityLow:
		return color.New(color.FgBlue)
	case ErrorSeverityMedium:
		return color.New(color.FgYellow)
	case ErrorSeverityHigh:
		return color.New(color.FgRed)
	case ErrorSeverityCritical:
		return color.New(color.FgRed, color.Bold)
	default:
		return color.New(color.FgWhite)
	}
}

// getSeverityIcon returns an icon for a given severity
func (f *ErrorFormatter) getSeverityIcon(severity ErrorSeverity) string {
	switch severity {
	case ErrorSeverityLow:
		return "ℹ️"
	case ErrorSeverityMedium:
		return "⚠️"
	case ErrorSeverityHigh:
		return "❌"
	case ErrorSeverityCritical:
		return "🚨"
	default:
		return "❓"
	}
}

// wrapText wraps text with indentation
func (f *ErrorFormatter) wrapText(text string, indent int) string {
	indentStr := strings.Repeat(" ", indent)
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = indentStr + line
	}
	return strings.Join(lines, "\n")
}

// ErrorBuilder helps build enhanced errors
type ErrorBuilder struct {
	err *EnhancedError
}

// NewError creates a new error builder
func NewError(code, message string) *ErrorBuilder {
	return &ErrorBuilder{
		err: &EnhancedError{
			Code:    code,
			Message: message,
			Context: make(map[string]interface{}),
		},
	}
}

// Category sets the error category
func (b *ErrorBuilder) Category(category ErrorCategory) *ErrorBuilder {
	b.err.Category = category
	return b
}

// Severity sets the error severity
func (b *ErrorBuilder) Severity(severity ErrorSeverity) *ErrorBuilder {
	b.err.Severity = severity
	return b
}

// Cause sets the underlying cause
func (b *ErrorBuilder) Cause(cause error) *ErrorBuilder {
	b.err.Cause = cause
	return b
}

// UserMessage sets the user-friendly message
func (b *ErrorBuilder) UserMessage(message string) *ErrorBuilder {
	b.err.UserMessage = message
	return b
}

// Explanation sets the explanation
func (b *ErrorBuilder) Explanation(explanation string) *ErrorBuilder {
	b.err.Explanation = explanation
	return b
}

// Suggestion adds a suggestion
func (b *ErrorBuilder) Suggestion(suggestion string) *ErrorBuilder {
	b.err.Suggestions = append(b.err.Suggestions, suggestion)
	return b
}

// Suggestions sets multiple suggestions
func (b *ErrorBuilder) Suggestions(suggestions ...string) *ErrorBuilder {
	b.err.Suggestions = suggestions
	return b
}

// Documentation sets the documentation link
func (b *ErrorBuilder) Documentation(url string) *ErrorBuilder {
	b.err.Documentation = url
	return b
}

// Example adds an example
func (b *ErrorBuilder) Example(example string) *ErrorBuilder {
	b.err.Examples = append(b.err.Examples, example)
	return b
}

// Context adds context information
func (b *ErrorBuilder) Context(key string, value interface{}) *ErrorBuilder {
	b.err.Context[key] = value
	return b
}

// Component sets the component name
func (b *ErrorBuilder) Component(component string) *ErrorBuilder {
	b.err.Component = component
	return b
}

// Build returns the enhanced error
func (b *ErrorBuilder) Build() *EnhancedError {
	return b.err
}

// Common error builders for frequent scenarios

// ConfigurationError creates a configuration-related error
func ConfigurationError(code, message string) *ErrorBuilder {
	return NewError(code, message).
		Category(CategoryConfiguration).
		Severity(ErrorSeverityMedium).
		Component("configuration")
}

// NetworkError creates a network-related error
func NetworkError(code, message string) *ErrorBuilder {
	return NewError(code, message).
		Category(CategoryNetwork).
		Severity(ErrorSeverityHigh).
		Component("network")
}

// PermissionError creates a permission-related error
func PermissionError(code, message string) *ErrorBuilder {
	return NewError(code, message).
		Category(CategoryPermission).
		Severity(ErrorSeverityHigh).
		Component("filesystem")
}

// DependencyError creates a dependency-related error
func DependencyError(code, message string) *ErrorBuilder {
	return NewError(code, message).
		Category(CategoryDependency).
		Severity(ErrorSeverityMedium).
		Component("dependencies")
}

// ValidationError creates a validation-related error
func ValidationError(code, message string) *ErrorBuilder {
	return NewError(code, message).
		Category(CategoryValidation).
		Severity(ErrorSeverityMedium).
		Component("validation")
}

// UsageError creates a usage-related error
func UsageError(code, message string) *ErrorBuilder {
	return NewError(code, message).
		Category(CategoryUsage).
		Severity(ErrorSeverityLow).
		Component("cli")
}

// Predefined common errors

// ErrConfigFileNotFound creates a config file not found error
func ErrConfigFileNotFound(path string) *EnhancedError {
	return ConfigurationError("CONFIG_FILE_NOT_FOUND", "Configuration file not found").
		UserMessage("Configuration file not found").
		Explanation(fmt.Sprintf("TypoSentinel couldn't find a configuration file at '%s'. This file contains important settings for how TypoSentinel should scan your project.", path)).
		Suggestions(
			"Run 'typosentinel init' to create a configuration file with smart defaults",
			"Create a .typosentinel.yaml file manually in your project root",
			"Use command-line flags to specify configuration options",
		).
		Example("typosentinel init").
		Documentation("https://docs.typosentinel.com/configuration").
		Context("path", path).
		Build()
}

// ErrInvalidConfiguration creates an invalid configuration error
func ErrInvalidConfiguration(field string, value interface{}) *EnhancedError {
	return ConfigurationError("INVALID_CONFIGURATION", "Invalid configuration").
		UserMessage("Configuration validation failed").
		Explanation(fmt.Sprintf("The configuration field '%s' has an invalid value '%v'. This prevents TypoSentinel from starting properly.", field, value)).
		Suggestions(
			"Check the configuration file syntax and field values",
			"Run 'typosentinel validate-config' to check your configuration",
			"Refer to the documentation for valid configuration options",
		).
		Documentation("https://docs.typosentinel.com/configuration/validation").
		Context("field", field).
		Context("value", value).
		Build()
}

// ErrNetworkTimeout creates a network timeout error
func ErrNetworkTimeout(url string) *EnhancedError {
	return NetworkError("NETWORK_TIMEOUT", "Network request timed out").
		UserMessage("Network connection timed out").
		Explanation(fmt.Sprintf("TypoSentinel couldn't connect to '%s' within the timeout period. This might be due to network issues or the service being unavailable.", url)).
		Suggestions(
			"Check your internet connection",
			"Verify that the URL is correct and accessible",
			"Try increasing the timeout value in configuration",
			"Check if you're behind a proxy or firewall",
		).
		Documentation("https://docs.typosentinel.com/troubleshooting/network").
		Context("url", url).
		Build()
}

// ErrPermissionDenied creates a permission denied error
func ErrPermissionDenied(path string) *EnhancedError {
	return PermissionError("PERMISSION_DENIED", "Permission denied").
		UserMessage("Permission denied").
		Explanation(fmt.Sprintf("TypoSentinel doesn't have permission to access '%s'. This is required for scanning your project.", path)).
		Suggestions(
			"Check file and directory permissions",
			"Run TypoSentinel with appropriate user privileges",
			"Ensure the path exists and is accessible",
		).
		Context("path", path).
		Build()
}

// ErrDependencyNotFound creates a dependency not found error
func ErrDependencyNotFound(dependency string) *EnhancedError {
	return DependencyError("DEPENDENCY_NOT_FOUND", "Required dependency not found").
		UserMessage("Required dependency not found").
		Explanation(fmt.Sprintf("TypoSentinel requires '%s' to function properly, but it's not installed or not in the system PATH.", dependency)).
		Suggestions(
			fmt.Sprintf("Install %s using your system package manager", dependency),
			"Ensure the dependency is in your system PATH",
			"Check the installation documentation for your operating system",
		).
		Documentation("https://docs.typosentinel.com/installation/dependencies").
		Context("dependency", dependency).
		Build()
}
