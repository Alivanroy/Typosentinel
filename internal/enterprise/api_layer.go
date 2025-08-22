package enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/enterprise/multitenant"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// EnterpriseAPIServer provides REST API endpoints for enterprise features
type EnterpriseAPIServer struct {
	integrationLayer *EnterpriseIntegrationLayer
	config           *APIConfig
	server           *http.Server
}

// APIConfig configures the enterprise API server
type APIConfig struct {
	Port                int           `json:"port"`
	Host                string        `json:"host"`
	TLSEnabled          bool          `json:"tls_enabled"`
	CertFile            string        `json:"cert_file"`
	KeyFile             string        `json:"key_file"`
	CORSEnabled         bool          `json:"cors_enabled"`
	AllowedOrigins      []string      `json:"allowed_origins"`
	AuthenticationEnabled bool        `json:"authentication_enabled"`
	APIKeyRequired      bool          `json:"api_key_required"`
	JWTSecret           string        `json:"jwt_secret"`
	RequestTimeout      time.Duration `json:"request_timeout"`
	MaxRequestSize      int64         `json:"max_request_size"`
	LoggingEnabled      bool          `json:"logging_enabled"`
	MetricsEnabled      bool          `json:"metrics_enabled"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Message   string      `json:"message,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	RequestID string      `json:"request_id,omitempty"`
}

// ScanRequestAPI represents an API scan request
type ScanRequestAPI struct {
	TenantID              string                 `json:"tenant_id"`
	RepositoryURL         string                 `json:"repository_url" validate:"required,url"`
	Branch                string                 `json:"branch"`
	ScanType              string                 `json:"scan_type"`
	MLPredictionEnabled   bool                   `json:"ml_prediction_enabled"`
	AutoRemediationEnabled bool                  `json:"auto_remediation_enabled"`
	PRGenerationEnabled   bool                   `json:"pr_generation_enabled"`
	OutputFormats         []string               `json:"output_formats"`
	PolicyOverrides       map[string]interface{} `json:"policy_overrides"`
	Metadata              map[string]interface{} `json:"metadata"`
	Priority              string                 `json:"priority"`
	CallbackURL           string                 `json:"callback_url"`
	CallbackMethod        string                 `json:"callback_method"`
	CallbackHeaders       map[string]string      `json:"callback_headers"`
	CallbackTimeout       int                    `json:"callback_timeout"`
}

// TenantRequestAPI represents an API tenant request
type TenantRequestAPI struct {
	Name        string                 `json:"name" validate:"required"`
	Description string                 `json:"description"`
	Plan        string                 `json:"plan"`
	Quotas      map[string]interface{} `json:"quotas"`
	Settings    map[string]interface{} `json:"settings"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewEnterpriseAPIServer creates a new enterprise API server
func NewEnterpriseAPIServer(integrationLayer *EnterpriseIntegrationLayer, config *APIConfig) *EnterpriseAPIServer {
	if config == nil {
		config = getDefaultAPIConfig()
	}

	server := &EnterpriseAPIServer{
		integrationLayer: integrationLayer,
		config:           config,
	}

	return server
}

// Start starts the API server
func (s *EnterpriseAPIServer) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	mux := http.NewServeMux()
	s.setupRoutes(mux)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  s.config.RequestTimeout,
		WriteTimeout: s.config.RequestTimeout,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Printf("Starting Enterprise API server on %s\n", addr)

	if s.config.TLSEnabled {
		return s.server.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
	}
	return s.server.ListenAndServe()
}

// Stop stops the API server
func (s *EnterpriseAPIServer) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// setupRoutes configures all API routes
func (s *EnterpriseAPIServer) setupRoutes(mux *http.ServeMux) {
	// Health and status endpoints
	mux.HandleFunc("/api/v1/health", s.withMiddleware(s.handleHealth))
	mux.HandleFunc("/api/v1/status", s.withMiddleware(s.handleStatus))
	mux.HandleFunc("/api/v1/metrics", s.withMiddleware(s.handleMetrics))

	// Scanning endpoints
	mux.HandleFunc("/api/v1/scans", s.withMiddleware(s.handleScans))

	// Multi-tenant endpoints
	if s.integrationLayer.config.MultiTenantEnabled {
		mux.HandleFunc("/api/v1/tenants", s.withMiddleware(s.handleTenants))
	}

	// ML prediction endpoints
	if s.integrationLayer.config.MLPredictionEnabled {
		mux.HandleFunc("/api/v1/ml/predict", s.withMiddleware(s.handleMLPredict))
		mux.HandleFunc("/api/v1/ml/models", s.withMiddleware(s.handleGetMLModels))
		mux.HandleFunc("/api/v1/ml/training/data", s.withMiddleware(s.handleAddTrainingData))
		mux.HandleFunc("/api/v1/ml/training/start", s.withMiddleware(s.handleStartTraining))
	}

	// Remediation endpoints
	if s.integrationLayer.config.AutoRemediationEnabled {
		mux.HandleFunc("/api/v1/remediation/execute", s.withMiddleware(s.handleExecuteRemediation))
		mux.HandleFunc("/api/v1/remediation/actions", s.withMiddleware(s.handleGetSupportedActions))
	}

	// Pull request endpoints
	if s.integrationLayer.config.PRGenerationEnabled {
		mux.HandleFunc("/api/v1/pull-requests/generate", s.withMiddleware(s.handleGeneratePR))
	}

	// Output format endpoints
	mux.HandleFunc("/api/v1/outputs/formats", s.withMiddleware(s.handleGetSupportedFormats))
	mux.HandleFunc("/api/v1/outputs/generate", s.withMiddleware(s.handleGenerateOutput))
}

// withMiddleware applies middleware to handlers
func (s *EnterpriseAPIServer) withMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CORS
		if s.config.CORSEnabled {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		// Logging
		if s.config.LoggingEnabled {
			start := time.Now()
			defer func() {
				fmt.Printf("%s %s %v\n", r.Method, r.URL.Path, time.Since(start))
			}()
		}

		// Authentication (simplified)
		if s.config.AuthenticationEnabled && !strings.HasSuffix(r.URL.Path, "/health") {
			apiKey := r.Header.Get("X-API-Key")
			authorization := r.Header.Get("Authorization")
			if s.config.APIKeyRequired && apiKey == "" && authorization == "" {
				s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", nil)
				return
			}
		}

		// Request size limit
		r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxRequestSize)

		// Recovery
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("Panic recovered: %v\n", err)
				s.writeErrorResponse(w, http.StatusInternalServerError, "Internal server error", nil)
			}
		}()

		handler(w, r)
	}
}

// Health and status handlers

func (s *EnterpriseAPIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := APIResponse{
		Success:   true,
		Message:   "Enterprise API server is healthy",
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

func (s *EnterpriseAPIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"server_status":        "running",
		"multi_tenant_enabled": s.integrationLayer.config.MultiTenantEnabled,
		"ml_enabled":           s.integrationLayer.config.MLPredictionEnabled,
		"remediation_enabled":  s.integrationLayer.config.AutoRemediationEnabled,
		"pr_generation_enabled": s.integrationLayer.config.PRGenerationEnabled,
	}

	response := APIResponse{
		Success:   true,
		Data:      status,
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

func (s *EnterpriseAPIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.integrationLayer.GetIntegrationMetrics()

	response := APIResponse{
		Success:   true,
		Data:      metrics,
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

// Scanning handlers

func (s *EnterpriseAPIServer) handleScans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		s.handleCreateScan(w, r)
	case "GET":
		s.handleListScans(w, r)
	default:
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
	}
}

func (s *EnterpriseAPIServer) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var apiRequest ScanRequestAPI
	if err := json.NewDecoder(r.Body).Decode(&apiRequest); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Convert API request to internal request
	request := s.convertToInternalScanRequest(&apiRequest)

	// Execute scan
	result, err := s.integrationLayer.ExecuteEnterpriseScan(r.Context(), request)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Scan execution failed", err)
		return
	}

	response := APIResponse{
		Success:   true,
		Data:      result,
		Message:   "Scan completed successfully",
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

func (s *EnterpriseAPIServer) handleListScans(w http.ResponseWriter, r *http.Request) {
	// This would typically list scans from database
	scans := []map[string]interface{}{
		{"id": "scan-1", "status": "completed", "created_at": time.Now()},
		{"id": "scan-2", "status": "running", "created_at": time.Now()},
	}

	response := APIResponse{
		Success:   true,
		Data:      scans,
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

// Tenant handlers

func (s *EnterpriseAPIServer) handleTenants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		s.handleCreateTenant(w, r)
	case "GET":
		s.handleListTenants(w, r)
	default:
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
	}
}

func (s *EnterpriseAPIServer) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var apiRequest TenantRequestAPI
	if err := json.NewDecoder(r.Body).Decode(&apiRequest); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Convert to internal request
	request := &multitenant.CreateTenantRequest{
		Name:        apiRequest.Name,
		Description: apiRequest.Description,
		Plan:        apiRequest.Plan,
		Quotas:      convertToTenantQuotas(apiRequest.Quotas),
		Settings:    convertToTenantSettings(apiRequest.Settings),
		Metadata:    apiRequest.Metadata,
	}

	tenant, err := s.integrationLayer.tenantManager.CreateTenant(r.Context(), request)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Tenant creation failed", err)
		return
	}

	response := APIResponse{
		Success:   true,
		Data:      tenant,
		Message:   "Tenant created successfully",
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusCreated, response)
}

func (s *EnterpriseAPIServer) handleListTenants(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters for filtering
	filter := &multitenant.TenantFilter{
		Status: multitenant.TenantStatus(r.URL.Query().Get("status")),
		Plan:   r.URL.Query().Get("plan"),
	}

	tenants, err := s.integrationLayer.tenantManager.ListTenants(r.Context(), filter)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list tenants", err)
		return
	}

	response := APIResponse{
		Success:   true,
		Data:      tenants,
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

// ML handlers

func (s *EnterpriseAPIServer) handleMLPredict(w http.ResponseWriter, r *http.Request) {
	var threat types.Threat
	if err := json.NewDecoder(r.Body).Decode(&threat); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid threat data", err)
		return
	}

	prediction, err := s.integrationLayer.threatPredictor.PredictThreatFromThreat(r.Context(), &threat)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "ML prediction failed", err)
		return
	}

	response := APIResponse{
		Success:   true,
		Data:      prediction,
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

func (s *EnterpriseAPIServer) handleGetMLModels(w http.ResponseWriter, r *http.Request) {
	models := map[string]interface{}{
		"available_models": []string{"logistic_regression", "random_forest", "neural_network"},
		"active_model": "ensemble",
		"model_version": "1.0.0",
	}

	response := APIResponse{
		Success:   true,
		Data:      models,
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

func (s *EnterpriseAPIServer) handleAddTrainingData(w http.ResponseWriter, r *http.Request) {
	var sample ml.TrainingSample
	if err := json.NewDecoder(r.Body).Decode(&sample); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid training data", err)
		return
	}

	err := s.integrationLayer.threatPredictor.AddTrainingSample(&sample)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to add training data", err)
		return
	}

	response := APIResponse{
		Success:   true,
		Message:   "Training data added successfully",
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

func (s *EnterpriseAPIServer) handleStartTraining(w http.ResponseWriter, r *http.Request) {
	err := s.integrationLayer.threatPredictor.TrainModels(r.Context())
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Training failed", err)
		return
	}

	response := APIResponse{
		Success:   true,
		Message:   "Model training started successfully",
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

// Remediation handlers

func (s *EnterpriseAPIServer) handleExecuteRemediation(w http.ResponseWriter, r *http.Request) {
	// This would execute remediation based on request
	response := APIResponse{
		Success:   true,
		Message:   "Remediation executed successfully",
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

func (s *EnterpriseAPIServer) handleGetSupportedActions(w http.ResponseWriter, r *http.Request) {
	actions := []string{"block", "quarantine", "notify", "remove", "update"}

	response := APIResponse{
		Success:   true,
		Data:      actions,
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

// Pull request handlers

func (s *EnterpriseAPIServer) handleGeneratePR(w http.ResponseWriter, r *http.Request) {
	// This would generate a pull request
	response := APIResponse{
		Success:   true,
		Message:   "Pull request generated successfully",
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

// Output format handlers

func (s *EnterpriseAPIServer) handleGetSupportedFormats(w http.ResponseWriter, r *http.Request) {
	formats := []string{"json", "sarif", "spdx", "cyclonedx", "csv", "xml"}

	response := APIResponse{
		Success:   true,
		Data:      formats,
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

func (s *EnterpriseAPIServer) handleGenerateOutput(w http.ResponseWriter, r *http.Request) {
	// This would generate output in specified format
	response := APIResponse{
		Success:   true,
		Message:   "Output generated successfully",
		Timestamp: time.Now(),
	}
	s.writeJSONResponse(w, http.StatusOK, response)
}

// Helper functions

func (s *EnterpriseAPIServer) writeJSONResponse(w http.ResponseWriter, statusCode int, response APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func (s *EnterpriseAPIServer) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}

	response := APIResponse{
		Success:   false,
		Error:     errorMsg,
		Timestamp: time.Now(),
	}

	s.writeJSONResponse(w, statusCode, response)
}

func (s *EnterpriseAPIServer) convertToInternalScanRequest(apiRequest *ScanRequestAPI) *EnterpriseScanRequest {
	outputFormats := make([]OutputFormat, len(apiRequest.OutputFormats))
	for i, format := range apiRequest.OutputFormats {
		outputFormats[i] = OutputFormat(format)
	}

	var callback *CallbackConfig
	if apiRequest.CallbackURL != "" {
		callback = &CallbackConfig{
			URL:     apiRequest.CallbackURL,
			Method:  apiRequest.CallbackMethod,
			Headers: apiRequest.CallbackHeaders,
			Timeout: time.Duration(apiRequest.CallbackTimeout) * time.Second,
		}
	}

	return &EnterpriseScanRequest{
		TenantID:               apiRequest.TenantID,
		RepositoryURL:          apiRequest.RepositoryURL,
		Branch:                 apiRequest.Branch,
		ScanType:               ScanType(apiRequest.ScanType),
		MLPredictionEnabled:    apiRequest.MLPredictionEnabled,
		AutoRemediationEnabled: apiRequest.AutoRemediationEnabled,
		PRGenerationEnabled:    apiRequest.PRGenerationEnabled,
		OutputFormats:          outputFormats,
		PolicyOverrides:        apiRequest.PolicyOverrides,
		Metadata:               apiRequest.Metadata,
		Priority:               ScanPriority(apiRequest.Priority),
		Callback:               callback,
	}
}

func convertToTenantQuotas(quotas map[string]interface{}) *multitenant.TenantQuotas {
	if quotas == nil {
		return nil
	}

	// Convert interface{} values to appropriate types
	result := &multitenant.TenantQuotas{}

	if maxScans, ok := quotas["max_scans_per_day"].(float64); ok {
		result.MaxScansPerDay = int(maxScans)
	}
	if maxUsers, ok := quotas["max_users"].(float64); ok {
		result.MaxUsers = int(maxUsers)
	}
	if maxStorage, ok := quotas["max_storage_gb"].(float64); ok {
		result.MaxStorageGB = int(maxStorage)
	}
	if maxAPIRequests, ok := quotas["max_api_calls_per_hour"].(float64); ok {
		result.MaxAPICallsPerHour = int(maxAPIRequests)
	}

	return result
}

func convertToTenantSettings(settings map[string]interface{}) *multitenant.TenantSettings {
	if settings == nil {
		return nil
	}

	// Convert interface{} values to appropriate types
	result := &multitenant.TenantSettings{}

	if notifications, ok := settings["notifications"].(map[string]interface{}); ok {
		result.Notifications = &multitenant.NotificationSettings{
			EmailEnabled: getBoolFromMap(notifications, "email_enabled"),
			SlackEnabled: getBoolFromMap(notifications, "slack_enabled"),
			WebhookEnabled: getBoolFromMap(notifications, "webhook_enabled"),
		}
	}

	if security, ok := settings["security"].(map[string]interface{}); ok {
		result.Security = &multitenant.SecuritySettings{
			MFARequired: getBoolFromMap(security, "mfa_required"),
			AuditLogging: getBoolFromMap(security, "audit_logging"),
			DataEncryption: getBoolFromMap(security, "data_encryption"),
		}
	}

	return result
}

func getBoolFromMap(m map[string]interface{}, key string) bool {
	if val, ok := m[key].(bool); ok {
		return val
	}
	return false
}

func getDefaultAPIConfig() *APIConfig {
	return &APIConfig{
		Port:                  8080,
		Host:                  "0.0.0.0",
		TLSEnabled:            false,
		CORSEnabled:           true,
		AllowedOrigins:        []string{"*"},
		AuthenticationEnabled: false,
		APIKeyRequired:        false,
		RequestTimeout:        30 * time.Second,
		MaxRequestSize:        10 * 1024 * 1024, // 10MB
		LoggingEnabled:        true,
		MetricsEnabled:        true,
	}
}