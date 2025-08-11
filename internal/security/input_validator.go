package security

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/microcosm-cc/bluemonday"
)

// InputValidator provides comprehensive input validation and sanitization
type InputValidator struct {
	validator    *validator.Validate
	htmlPolicy   *bluemonday.Policy
	maxJSONDepth int
	maxSize      int64
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// ValidationResult contains validation results
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
}

// NewInputValidator creates a new input validator
func NewInputValidator() *InputValidator {
	v := validator.New()
	
	// Register custom validators
	v.RegisterValidation("package_name", validatePackageName)
	v.RegisterValidation("version", validateVersion)
	v.RegisterValidation("url_safe", validateURLSafe)
	v.RegisterValidation("no_sql_injection", validateNoSQLInjection)
	v.RegisterValidation("no_xss", validateNoXSS)
	v.RegisterValidation("safe_filename", validateSafeFilename)
	v.RegisterValidation("api_key", validateAPIKey)
	v.RegisterValidation("jwt_token", validateJWTToken)
	
	// Create strict HTML policy
	htmlPolicy := bluemonday.StrictPolicy()
	
	return &InputValidator{
		validator:    v,
		htmlPolicy:   htmlPolicy,
		maxJSONDepth: 10,
		maxSize:      10 * 1024 * 1024, // 10MB
	}
}

// ValidateStruct validates a struct using validation tags
func (iv *InputValidator) ValidateStruct(s interface{}) ValidationResult {
	err := iv.validator.Struct(s)
	if err == nil {
		return ValidationResult{Valid: true}
	}
	
	var errors []ValidationError
	for _, err := range err.(validator.ValidationErrors) {
		errors = append(errors, ValidationError{
			Field:   err.Field(),
			Tag:     err.Tag(),
			Value:   fmt.Sprintf("%v", err.Value()),
			Message: getValidationMessage(err),
		})
	}
	
	return ValidationResult{
		Valid:  false,
		Errors: errors,
	}
}

// SanitizeString sanitizes a string input
func (iv *InputValidator) SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Normalize unicode
	input = strings.TrimSpace(input)
	
	// Remove control characters except newlines and tabs
	var result strings.Builder
	for _, r := range input {
		if unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' {
			continue
		}
		result.WriteRune(r)
	}
	
	return result.String()
}

// SanitizeHTML sanitizes HTML content
func (iv *InputValidator) SanitizeHTML(input string) string {
	return iv.htmlPolicy.Sanitize(input)
}

// ValidateJSON validates JSON structure and depth
func (iv *InputValidator) ValidateJSON(data []byte) ValidationResult {
	if len(data) > int(iv.maxSize) {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:   "json",
				Tag:     "max_size",
				Message: fmt.Sprintf("JSON size exceeds maximum of %d bytes", iv.maxSize),
			}},
		}
	}
	
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:   "json",
				Tag:     "invalid_json",
				Message: "Invalid JSON format",
			}},
		}
	}
	
	depth := calculateJSONDepth(obj)
	if depth > iv.maxJSONDepth {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:   "json",
				Tag:     "max_depth",
				Message: fmt.Sprintf("JSON depth exceeds maximum of %d", iv.maxJSONDepth),
			}},
		}
	}
	
	return ValidationResult{Valid: true}
}

// ValidatePackageName validates package names
func (iv *InputValidator) ValidatePackageName(name string) ValidationResult {
	name = iv.SanitizeString(name)
	
	// Check length
	if len(name) == 0 || len(name) > 214 {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:   "package_name",
				Tag:     "length",
				Message: "Package name must be between 1 and 214 characters",
			}},
		}
	}
	
	// Check for valid characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validName.MatchString(name) {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:   "package_name",
				Tag:     "format",
				Message: "Package name contains invalid characters",
			}},
		}
	}
	
	// Check for suspicious patterns
	suspiciousPatterns := []string{
		"../", "./", "\\", "<script", "javascript:", "data:",
		"eval(", "exec(", "system(", "shell_exec(",
	}
	
	lowerName := strings.ToLower(name)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerName, pattern) {
			return ValidationResult{
				Valid: false,
				Errors: []ValidationError{{
					Field:   "package_name",
					Tag:     "suspicious",
					Message: "Package name contains suspicious patterns",
				}},
			}
		}
	}
	
	return ValidationResult{Valid: true}
}

// ValidateURL validates and sanitizes URLs
func (iv *InputValidator) ValidateURL(rawURL string) (string, ValidationResult) {
	rawURL = iv.SanitizeString(rawURL)
	
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:   "url",
				Tag:     "invalid",
				Message: "Invalid URL format",
			}},
		}
	}
	
	// Check scheme
	allowedSchemes := []string{"http", "https", "git", "ssh"}
	schemeAllowed := false
	for _, scheme := range allowedSchemes {
		if parsedURL.Scheme == scheme {
			schemeAllowed = true
			break
		}
	}
	
	if !schemeAllowed {
		return "", ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:   "url",
				Tag:     "scheme",
				Message: "URL scheme not allowed",
			}},
		}
	}
	
	// Check for suspicious patterns
	if strings.Contains(parsedURL.String(), "javascript:") ||
		strings.Contains(parsedURL.String(), "data:") ||
		strings.Contains(parsedURL.String(), "vbscript:") {
		return "", ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:   "url",
				Tag:     "suspicious",
				Message: "URL contains suspicious content",
			}},
		}
	}
	
	return parsedURL.String(), ValidationResult{Valid: true}
}

// ValidateAPIKey validates API key format
func (iv *InputValidator) ValidateAPIKey(key string) ValidationResult {
	key = iv.SanitizeString(key)
	
	// Check length (minimum 16 characters)
	if len(key) < 16 {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:   "api_key",
				Tag:     "length",
				Message: "API key must be at least 16 characters",
			}},
		}
	}
	
	// Check for valid characters (alphanumeric + some special chars)
	validKey := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validKey.MatchString(key) {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:   "api_key",
				Tag:     "format",
				Message: "API key contains invalid characters",
			}},
		}
	}
	
	return ValidationResult{Valid: true}
}

// Custom validation functions

func validatePackageName(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	if len(name) == 0 || len(name) > 214 {
		return false
	}
	
	validName := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	return validName.MatchString(name)
}

func validateVersion(fl validator.FieldLevel) bool {
	version := fl.Field().String()
	// Semantic version pattern
	semverPattern := regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
	return semverPattern.MatchString(version)
}

func validateURLSafe(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	// Check for URL-unsafe characters
	unsafeChars := []string{"<", ">", "\"", " ", "{", "}", "|", "\\", "^", "`"}
	for _, char := range unsafeChars {
		if strings.Contains(value, char) {
			return false
		}
	}
	return true
}

func validateNoSQLInjection(fl validator.FieldLevel) bool {
	value := strings.ToLower(fl.Field().String())
	sqlPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
		"union", "select", "insert", "update", "delete",
		"drop", "create", "alter", "exec", "execute",
	}
	
	for _, pattern := range sqlPatterns {
		if strings.Contains(value, pattern) {
			return false
		}
	}
	return true
}

func validateNoXSS(fl validator.FieldLevel) bool {
	value := strings.ToLower(fl.Field().String())
	xssPatterns := []string{
		"<script", "</script>", "javascript:", "vbscript:",
		"onload=", "onerror=", "onclick=", "onmouseover=",
		"eval(", "alert(", "confirm(", "prompt(",
	}
	
	for _, pattern := range xssPatterns {
		if strings.Contains(value, pattern) {
			return false
		}
	}
	return true
}

func validateSafeFilename(fl validator.FieldLevel) bool {
	filename := fl.Field().String()
	// Check for path traversal and unsafe characters
	unsafePatterns := []string{
		"../", "./", "\\", "/", ":", "*", "?", "\"", "<", ">", "|",
	}
	
	for _, pattern := range unsafePatterns {
		if strings.Contains(filename, pattern) {
			return false
		}
	}
	return true
}

func validateAPIKey(fl validator.FieldLevel) bool {
	key := fl.Field().String()
	if len(key) < 16 {
		return false
	}
	
	validKey := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	return validKey.MatchString(key)
}

func validateJWTToken(fl validator.FieldLevel) bool {
	token := fl.Field().String()
	// JWT tokens have 3 parts separated by dots
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	
	// Each part should be base64url encoded
	for _, part := range parts {
		if len(part) == 0 {
			return false
		}
	}
	
	return true
}

// Helper functions

func calculateJSONDepth(obj interface{}) int {
	switch v := obj.(type) {
	case map[string]interface{}:
		maxDepth := 0
		for _, value := range v {
			depth := calculateJSONDepth(value)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
		return maxDepth + 1
	case []interface{}:
		maxDepth := 0
		for _, value := range v {
			depth := calculateJSONDepth(value)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
		return maxDepth + 1
	default:
		return 1
	}
}

func getValidationMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", err.Field())
	case "email":
		return fmt.Sprintf("%s must be a valid email address", err.Field())
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", err.Field(), err.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters long", err.Field(), err.Param())
	case "package_name":
		return fmt.Sprintf("%s must be a valid package name", err.Field())
	case "version":
		return fmt.Sprintf("%s must be a valid semantic version", err.Field())
	case "url_safe":
		return fmt.Sprintf("%s contains URL-unsafe characters", err.Field())
	case "no_sql_injection":
		return fmt.Sprintf("%s contains potential SQL injection patterns", err.Field())
	case "no_xss":
		return fmt.Sprintf("%s contains potential XSS patterns", err.Field())
	case "safe_filename":
		return fmt.Sprintf("%s is not a safe filename", err.Field())
	case "api_key":
		return fmt.Sprintf("%s is not a valid API key format", err.Field())
	case "jwt_token":
		return fmt.Sprintf("%s is not a valid JWT token format", err.Field())
	default:
		return fmt.Sprintf("%s is invalid", err.Field())
	}
}

// Request validation structures

// ScanRequest represents a scan request with validation
type ScanRequest struct {
	PackageName    string            `json:"package_name" validate:"required,package_name,no_sql_injection,no_xss"`
	Version        string            `json:"version" validate:"omitempty,version"`
	Registry       string            `json:"registry" validate:"required,oneof=npm pypi rubygems maven"`
	RepositoryURL  string            `json:"repository_url" validate:"omitempty,url"`
	Timeout        int               `json:"timeout" validate:"min=1,max=3600"`
	Options        map[string]string `json:"options" validate:"dive,no_sql_injection,no_xss"`
}

// UserRequest represents a user creation request
type UserRequest struct {
	Username string `json:"username" validate:"required,min=3,max=50,alphanum,no_sql_injection"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=128"`
	Role     string `json:"role" validate:"required,oneof=admin user viewer"`
}

// APIKeyRequest represents an API key creation request
type APIKeyRequest struct {
	Name        string    `json:"name" validate:"required,min=1,max=100,no_sql_injection,no_xss"`
	Description string    `json:"description" validate:"max=500,no_xss"`
	ExpiresAt   time.Time `json:"expires_at" validate:"required"`
	Permissions []string  `json:"permissions" validate:"required,dive,oneof=read write admin"`
}