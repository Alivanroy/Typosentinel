// Package errors provides structured error handling for Typosentinel
// This package implements comprehensive error types with context and categorization
package errors

import (
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// ErrorCode represents different categories of errors
type ErrorCode string

const (
	// General errors
	INTERNAL_ERROR     ErrorCode = "INTERNAL_ERROR"
	INVALID_INPUT      ErrorCode = "INVALID_INPUT"
	UNAUTHORIZED       ErrorCode = "UNAUTHORIZED"
	FORBIDDEN          ErrorCode = "FORBIDDEN"
	RATE_LIMITED       ErrorCode = "RATE_LIMITED"
	NOT_FOUND_ERROR    ErrorCode = "NOT_FOUND_ERROR"
	VALIDATION_ERROR   ErrorCode = "VALIDATION_ERROR"

	// Package scanning errors
	PACKAGE_NOT_FOUND  ErrorCode = "PACKAGE_NOT_FOUND"
	SCAN_FAILED        ErrorCode = "SCAN_FAILED"
	INVALID_PACKAGE    ErrorCode = "INVALID_PACKAGE"

	// Database errors
	DB_CONNECTION_ERROR ErrorCode = "DB_CONNECTION_ERROR"
	DB_QUERY_ERROR     ErrorCode = "DB_QUERY_ERROR"
	DB_TRANSACTION_ERROR ErrorCode = "DB_TRANSACTION_ERROR"

	// Cache errors
	CACHE_ERROR        ErrorCode = "CACHE_ERROR"
	CACHE_MISS         ErrorCode = "CACHE_MISS"

	// ML/AI errors
	ML_MODEL_ERROR     ErrorCode = "ML_MODEL_ERROR"
	ML_PREDICTION_ERROR ErrorCode = "ML_PREDICTION_ERROR"

	// Configuration errors
	CONFIG_ERROR       ErrorCode = "CONFIG_ERROR"
	CONFIG_VALIDATION_ERROR ErrorCode = "CONFIG_VALIDATION_ERROR"

	// Input validation errors
	ErrCodeValidation ErrorCode = "VALIDATION_ERROR"
	ErrCodeInvalidInput ErrorCode = "INVALID_INPUT"
	ErrCodeMissingRequired ErrorCode = "MISSING_REQUIRED"
	
	// Network and external service errors
	ErrCodeNetwork ErrorCode = "NETWORK_ERROR"
	ErrCodeTimeout ErrorCode = "TIMEOUT_ERROR"
	ErrCodeRateLimit ErrorCode = "RATE_LIMIT_ERROR"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	
	// Resource errors
	ErrCodeNotFound ErrorCode = "NOT_FOUND"
	ErrCodeAlreadyExists ErrorCode = "ALREADY_EXISTS"
	ErrCodePermissionDenied ErrorCode = "PERMISSION_DENIED"
	ErrCodeQuotaExceeded ErrorCode = "QUOTA_EXCEEDED"
	
	// Processing errors
	ErrCodeProcessing ErrorCode = "PROCESSING_ERROR"
	ErrCodeParsing ErrorCode = "PARSING_ERROR"
	ErrCodeEncoding ErrorCode = "ENCODING_ERROR"
	ErrCodeDecoding ErrorCode = "DECODING_ERROR"
	
	// Database errors
	ErrCodeDatabase ErrorCode = "DATABASE_ERROR"
	ErrCodeTransaction ErrorCode = "TRANSACTION_ERROR"
	ErrCodeConstraint ErrorCode = "CONSTRAINT_ERROR"
	
	// Authentication and authorization errors
	ErrCodeAuth ErrorCode = "AUTH_ERROR"
	ErrCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden ErrorCode = "FORBIDDEN"
	ErrCodeTokenExpired ErrorCode = "TOKEN_EXPIRED"
	
	// Configuration errors
	ErrCodeConfig ErrorCode = "CONFIG_ERROR"
	ErrCodeMissingConfig ErrorCode = "MISSING_CONFIG"
	ErrCodeInvalidConfig ErrorCode = "INVALID_CONFIG"
	
	// Internal system errors
	ErrCodeInternal ErrorCode = "INTERNAL_ERROR"
	ErrCodePanic ErrorCode = "PANIC_ERROR"
	ErrCodeUnknown ErrorCode = "UNKNOWN_ERROR"
)

// Severity represents the severity level of an error
type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// AppError represents a structured application error
type AppError struct {
	Code      ErrorCode              `json:"code"`
	Message   string                 `json:"message"`
	Cause     error                  `json:"-"`
	Context   map[string]interface{} `json:"context,omitempty"`
	Severity  Severity               `json:"severity"`
	Timestamp time.Time              `json:"timestamp"`
	StackTrace string                `json:"stack_trace,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	Retryable bool                   `json:"retryable"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause error
func (e *AppError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target error
func (e *AppError) Is(target error) bool {
	if appErr, ok := target.(*AppError); ok {
		return e.Code == appErr.Code
	}
	return false
}

// WithContext adds context information to the error
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithRequestID adds a request ID to the error
func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// WithUserID adds a user ID to the error
func (e *AppError) WithUserID(userID string) *AppError {
	e.UserID = userID
	return e
}

// IsRetryable returns whether the error is retryable
func (e *AppError) IsRetryable() bool {
	return e.Retryable
}

// GetSeverity returns the error severity
func (e *AppError) GetSeverity() Severity {
	return e.Severity
}

// GetCode returns the error code
func (e *AppError) GetCode() ErrorCode {
	return e.Code
}

// New creates a new AppError
func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:      code,
		Message:   message,
		Severity:  getSeverityForCode(code),
		Timestamp: time.Now(),
		Retryable: isRetryableCode(code),
		StackTrace: getStackTrace(),
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, code ErrorCode, message string) *AppError {
	appErr := New(code, message)
	appErr.Cause = err
	return appErr
}

// Wrapf wraps an existing error with formatted message
func Wrapf(err error, code ErrorCode, format string, args ...interface{}) *AppError {
	return Wrap(err, code, fmt.Sprintf(format, args...))
}

// Newf creates a new AppError with formatted message
func Newf(code ErrorCode, format string, args ...interface{}) *AppError {
	return New(code, fmt.Sprintf(format, args...))
}

// Validation error constructors
func NewValidationError(message string) *AppError {
	return New(ErrCodeValidation, message)
}

func NewInvalidInputError(field, value string) *AppError {
	return New(ErrCodeInvalidInput, fmt.Sprintf("invalid value '%s' for field '%s'", value, field))
}

func NewMissingRequiredError(field string) *AppError {
	return New(ErrCodeMissingRequired, fmt.Sprintf("required field '%s' is missing", field))
}

// Network error constructors
func NewNetworkError(message string) *AppError {
	return New(ErrCodeNetwork, message)
}

func NewTimeoutError(operation string, timeout time.Duration) *AppError {
	return New(ErrCodeTimeout, fmt.Sprintf("operation '%s' timed out after %v", operation, timeout))
}

func NewRateLimitError(limit int, window time.Duration) *AppError {
	return New(ErrCodeRateLimit, fmt.Sprintf("rate limit exceeded: %d requests per %v", limit, window))
}

// Resource error constructors
func NewNotFoundError(resource, id string) *AppError {
	return New(ErrCodeNotFound, fmt.Sprintf("%s with id '%s' not found", resource, id))
}

func NewAlreadyExistsError(resource, id string) *AppError {
	return New(ErrCodeAlreadyExists, fmt.Sprintf("%s with id '%s' already exists", resource, id))
}

// Processing error constructors
func NewProcessingError(message string) *AppError {
	return New(ErrCodeProcessing, message)
}

func NewParsingError(format, input string) *AppError {
	return New(ErrCodeParsing, fmt.Sprintf("failed to parse %s: %s", format, input))
}

// Database error constructors
func NewDatabaseError(operation string, err error) *AppError {
	return Wrap(err, ErrCodeDatabase, fmt.Sprintf("database operation '%s' failed", operation))
}

// Authentication error constructors
func NewUnauthorizedError(message string) *AppError {
	return New(ErrCodeUnauthorized, message)
}

func NewForbiddenError(resource string) *AppError {
	return New(ErrCodeForbidden, fmt.Sprintf("access to '%s' is forbidden", resource))
}

// Configuration error constructors
func NewConfigError(key, reason string) *AppError {
	return New(ErrCodeConfig, fmt.Sprintf("configuration error for '%s': %s", key, reason))
}

// Internal error constructors
func NewInternalError(message string) *AppError {
	return New(ErrCodeInternal, message)
}

func NewPanicError(recovered interface{}) *AppError {
	return New(ErrCodePanic, fmt.Sprintf("panic recovered: %v", recovered))
}

// Helper functions

// getSeverityForCode returns the default severity for an error code
func getSeverityForCode(code ErrorCode) Severity {
	switch code {
	case ErrCodeValidation, ErrCodeInvalidInput, ErrCodeMissingRequired:
		return SeverityLow
	case ErrCodeNotFound, ErrCodeTimeout, ErrCodeParsing:
		return SeverityMedium
	case ErrCodeNetwork, ErrCodeDatabase, ErrCodeAuth:
		return SeverityHigh
	case ErrCodeInternal, ErrCodePanic:
		return SeverityCritical
	default:
		return SeverityMedium
	}
}

// isRetryableCode returns whether an error code represents a retryable error
func isRetryableCode(code ErrorCode) bool {
	switch code {
	case ErrCodeNetwork, ErrCodeTimeout, ErrCodeRateLimit, ErrCodeServiceUnavailable:
		return true
	case ErrCodeValidation, ErrCodeInvalidInput, ErrCodeNotFound, ErrCodeUnauthorized, ErrCodeForbidden:
		return false
	default:
		return false
	}
}

// getStackTrace captures the current stack trace
func getStackTrace() string {
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// IsAppError checks if an error is an AppError
func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

// GetAppError extracts an AppError from an error chain
func GetAppError(err error) *AppError {
	if appErr, ok := err.(*AppError); ok {
		return appErr
	}
	return nil
}

// HasCode checks if an error has a specific error code
func HasCode(err error, code ErrorCode) bool {
	if appErr := GetAppError(err); appErr != nil {
		return appErr.Code == code
	}
	return false
}

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	if appErr := GetAppError(err); appErr != nil {
		return appErr.IsRetryable()
	}
	return false
}

// GetSeverity returns the severity of an error
func GetSeverity(err error) Severity {
	if appErr := GetAppError(err); appErr != nil {
		return appErr.GetSeverity()
	}
	return SeverityMedium
}

// ErrorList represents a collection of errors
type ErrorList struct {
	Errors []*AppError `json:"errors"`
}

// NewErrorList creates a new error list
func NewErrorList() *ErrorList {
	return &ErrorList{
		Errors: make([]*AppError, 0),
	}
}

// Add adds an error to the list
func (el *ErrorList) Add(err *AppError) {
	el.Errors = append(el.Errors, err)
}

// AddError adds a generic error to the list
func (el *ErrorList) AddError(err error) {
	if appErr := GetAppError(err); appErr != nil {
		el.Add(appErr)
	} else {
		el.Add(Wrap(err, ErrCodeUnknown, "unknown error"))
	}
}

// HasErrors returns true if the list contains errors
func (el *ErrorList) HasErrors() bool {
	return len(el.Errors) > 0
}

// Error implements the error interface
func (el *ErrorList) Error() string {
	if len(el.Errors) == 0 {
		return "no errors"
	}
	if len(el.Errors) == 1 {
		return el.Errors[0].Error()
	}
	return fmt.Sprintf("multiple errors: %d errors occurred", len(el.Errors))
}

// First returns the first error in the list
func (el *ErrorList) First() *AppError {
	if len(el.Errors) > 0 {
		return el.Errors[0]
	}
	return nil
}

// Count returns the number of errors
func (el *ErrorList) Count() int {
	return len(el.Errors)
}

// Clear removes all errors from the list
func (el *ErrorList) Clear() {
	el.Errors = el.Errors[:0]
}

// NewAppError creates a new AppError with the given code and message
func NewAppError(code ErrorCode, message string) *AppError {
	return New(code, message)
}

// GetHTTPStatus returns the appropriate HTTP status code for an error
func GetHTTPStatus(err error) int {
	if appErr := GetAppError(err); appErr != nil {
		switch appErr.Code {
		case ErrCodeUnauthorized:
			return http.StatusUnauthorized
		case ErrCodeForbidden:
			return http.StatusForbidden
		case ErrCodeNotFound:
			return http.StatusNotFound
		case ErrCodeInvalidInput, ErrCodeValidation:
			return http.StatusBadRequest
		case ErrCodeRateLimit:
			return http.StatusTooManyRequests
		case ErrCodeInternal:
			return http.StatusInternalServerError
		default:
			return http.StatusInternalServerError
		}
	}
	return http.StatusInternalServerError
}