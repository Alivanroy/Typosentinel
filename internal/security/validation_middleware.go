package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ValidationMiddleware provides comprehensive input validation for API endpoints
type ValidationMiddleware struct {
	validator     *InputValidator
	maxBodySize   int64
	enableLogging bool
	logger        Logger
}

// Logger interface for validation middleware
type Logger interface {
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}

// ValidationConfig holds configuration for validation middleware
type ValidationConfig struct {
	MaxBodySize   int64
	EnableLogging bool
	Logger        Logger
}

// NewValidationMiddleware creates a new validation middleware
func NewValidationMiddleware(config ValidationConfig) *ValidationMiddleware {
	if config.MaxBodySize == 0 {
		config.MaxBodySize = 10 * 1024 * 1024 // 10MB default
	}
	
	return &ValidationMiddleware{
		validator:     NewInputValidator(),
		maxBodySize:   config.MaxBodySize,
		enableLogging: config.EnableLogging,
		logger:        config.Logger,
	}
}

// ValidateRequest returns a Gin middleware that validates incoming requests
func (vm *ValidationMiddleware) ValidateRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		// Register custom validation functions
		vm.registerCustomValidators()
		
		// Validate request headers
		if err := vm.validateHeaders(c); err != nil {
			vm.logValidationError(c, "header_validation", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request headers",
				"details": err.Error(),
			})
			c.Abort()
			return
		}
		
		// Validate query parameters
		if err := vm.validateQueryParams(c); err != nil {
			vm.logValidationError(c, "query_validation", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid query parameters",
				"details": err.Error(),
			})
			c.Abort()
			return
		}
		
		// Validate request body for POST/PUT/PATCH requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			if err := vm.validateRequestBody(c); err != nil {
				vm.logValidationError(c, "body_validation", err)
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid request body",
					"details": err.Error(),
				})
				c.Abort()
				return
			}
		}
		
		// Log successful validation
		if vm.enableLogging && vm.logger != nil {
			vm.logger.Info("Request validation successful",
				"method", c.Request.Method,
				"path", c.Request.URL.Path,
				"duration", time.Since(start),
				"client_ip", c.ClientIP(),
			)
		}
		
		c.Next()
	}
}

// validateHeaders validates HTTP headers for security issues
func (vm *ValidationMiddleware) validateHeaders(c *gin.Context) error {
	// Check for suspicious headers
	suspiciousHeaders := []string{
		"X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
		"User-Agent", "Referer", "Origin",
	}
	
	for _, header := range suspiciousHeaders {
		value := c.GetHeader(header)
		if value != "" {
			// Sanitize header value
			sanitized := vm.validator.SanitizeString(value)
			if sanitized != value {
				return fmt.Errorf("suspicious content in header %s", header)
			}
			
			// Check for injection patterns
			if !vm.validateStringForInjection(value) {
				return fmt.Errorf("potential injection in header %s", header)
			}
		}
	}
	
	// Validate Content-Type for POST/PUT/PATCH requests
	if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
		contentType := c.GetHeader("Content-Type")
		if contentType == "" {
			return fmt.Errorf("missing Content-Type header")
		}
		
		allowedTypes := []string{
			"application/json",
			"application/x-www-form-urlencoded",
			"multipart/form-data",
		}
		
		valid := false
		for _, allowedType := range allowedTypes {
			if strings.HasPrefix(contentType, allowedType) {
				valid = true
				break
			}
		}
		
		if !valid {
			return fmt.Errorf("unsupported Content-Type: %s", contentType)
		}
	}
	
	return nil
}

// validateQueryParams validates URL query parameters
func (vm *ValidationMiddleware) validateQueryParams(c *gin.Context) error {
	for key, values := range c.Request.URL.Query() {
		// Validate parameter name
		if !vm.validateStringForInjection(key) {
			return fmt.Errorf("potential injection in query parameter name: %s", key)
		}
		
		// Validate parameter values
		for _, value := range values {
			if !vm.validateStringForInjection(value) {
				return fmt.Errorf("potential injection in query parameter %s: %s", key, value)
			}
			
			// Check parameter length
			if len(value) > 1024 {
				return fmt.Errorf("query parameter %s exceeds maximum length", key)
			}
		}
	}
	
	return nil
}

// validateRequestBody validates the request body
func (vm *ValidationMiddleware) validateRequestBody(c *gin.Context) error {
	// Check content length
	if c.Request.ContentLength > vm.maxBodySize {
		return fmt.Errorf("request body too large: %d bytes (max: %d)", c.Request.ContentLength, vm.maxBodySize)
	}
	
	// Read body
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, vm.maxBodySize))
	if err != nil {
		return fmt.Errorf("failed to read request body: %v", err)
	}
	
	// Restore body for further processing
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	
	// Validate JSON structure if Content-Type is JSON
	contentType := c.GetHeader("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		result := vm.validator.ValidateJSON(body)
		if !result.Valid {
			return fmt.Errorf("invalid JSON structure: %v", result.Errors)
		}
		
		// Parse and validate JSON content
		var jsonData interface{}
		if err := json.Unmarshal(body, &jsonData); err != nil {
			return fmt.Errorf("failed to parse JSON: %v", err)
		}
		
		// Recursively validate JSON values
		if err := vm.validateJSONValues(jsonData); err != nil {
			return err
		}
	}
	
	return nil
}

// validateJSONValues recursively validates JSON values for injection attacks
func (vm *ValidationMiddleware) validateJSONValues(data interface{}) error {
	switch v := data.(type) {
	case string:
		if !vm.validateStringForInjection(v) {
			return fmt.Errorf("potential injection in JSON string value: %s", v)
		}
	case map[string]interface{}:
		for key, value := range v {
			if !vm.validateStringForInjection(key) {
				return fmt.Errorf("potential injection in JSON key: %s", key)
			}
			if err := vm.validateJSONValues(value); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, item := range v {
			if err := vm.validateJSONValues(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateStringForInjection checks a string for various injection patterns
func (vm *ValidationMiddleware) validateStringForInjection(value string) bool {
	// Check for SQL injection
	sqlPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
		"union", "select", "insert", "update", "delete", "drop",
		"exec", "execute", "declare", "cast", "convert",
	}
	
	// Check for XSS
	xssPatterns := []string{
		"<script", "</script>", "javascript:", "vbscript:",
		"onload=", "onerror=", "onclick=", "onmouseover=",
		"<iframe", "<object", "<embed", "<form",
	}
	
	// Check for command injection
	cmdPatterns := []string{
		";", "|", "&", "`", "$(", "${",
		"eval(", "exec(", "system(", "shell_exec(",
	}
	
	// Check for path traversal
	pathPatterns := []string{
		"../", "..\\", "..%2f", "..%5c",
		"/etc/", "\\windows\\", "c:\\",
	}
	
	allPatterns := append(sqlPatterns, xssPatterns...)
	allPatterns = append(allPatterns, cmdPatterns...)
	allPatterns = append(allPatterns, pathPatterns...)
	
	valueLower := strings.ToLower(value)
	for _, pattern := range allPatterns {
		if strings.Contains(valueLower, strings.ToLower(pattern)) {
			return false
		}
	}
	
	return true
}

// logValidationError logs validation errors
func (vm *ValidationMiddleware) logValidationError(c *gin.Context, validationType string, err error) {
	if vm.enableLogging && vm.logger != nil {
		vm.logger.Error("Validation error",
			"type", validationType,
			"error", err.Error(),
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"client_ip", c.ClientIP(),
			"user_agent", c.GetHeader("User-Agent"),
		)
	}
}

// ValidateStructMiddleware creates middleware for validating specific struct types
func (vm *ValidationMiddleware) ValidateStructMiddleware(structType interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		var data interface{}
		
		// Bind JSON to struct
		if err := c.ShouldBindJSON(&data); err != nil {
			vm.logValidationError(c, "struct_binding", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid JSON structure",
				"details": err.Error(),
			})
			c.Abort()
			return
		}
		
		// Validate struct
		result := vm.validator.ValidateStruct(data)
		if !result.Valid {
			vm.logValidationError(c, "struct_validation", fmt.Errorf("validation failed: %v", result.Errors))
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Validation failed",
				"details": result.Errors,
			})
			c.Abort()
			return
		}
		
		// Store validated data in context
		c.Set("validated_data", data)
		c.Next()
	}
}

// registerCustomValidators registers custom validation functions
func (vm *ValidationMiddleware) registerCustomValidators() {
	// Register custom validators with the input validator
	vm.validator.RegisterCustomValidator("package_name", validatePackageName)
	vm.validator.RegisterCustomValidator("no_path_traversal", validateNoPathTraversal)
	vm.validator.RegisterCustomValidator("no_command_injection", validateNoCommandInjection)
	vm.validator.RegisterCustomValidator("safe_regex", validateSafeRegex)
	vm.validator.RegisterCustomValidator("no_ldap_injection", validateNoLDAPInjection)
}



// GetValidatedData retrieves validated data from context
func GetValidatedData(c *gin.Context) (interface{}, bool) {
	return c.Get("validated_data")
}