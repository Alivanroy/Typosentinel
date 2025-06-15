package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/typosentinel/typosentinel/pkg/types"
)

// GetOrganization handles GET /api/organizations/{id}
func (s *Server) GetOrganization(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid organization ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user belongs to organization
	if user.OrganizationID != orgID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// TODO: Implement database query
	org := &types.Organization{
		ID:   orgID,
		Name: "Example Organization",
		Settings: &types.OrganizationSettings{
			CustomRegistries: []*types.CustomRegistry{
				{
					ID:       1,
					Name:     "Internal NPM",
					Type:     "npm",
					URL:      "https://npm.internal.company.com",
					Enabled:  true,
					Priority: 1,
				},
				{
					ID:       2,
					Name:     "JFrog Artifactory",
					Type:     "maven",
					URL:      "https://artifactory.company.com/maven",
					Enabled:  true,
					Priority: 2,
				},
			},
			ScanSettings: &types.ScanSettings{
				AutoScan:              true,
				ScanOnPush:            true,
				ScanSchedule:          "0 2 * * *", // Daily at 2 AM
				RiskThreshold:         0.7,
				IncludeDevDependencies: false,
				MaxDepth:              10,
			},
			NotificationSettings: &types.NotificationSettings{
				EmailEnabled:    true,
				SlackEnabled:    false,
				WebhookEnabled:  true,
				WebhookURL:      "https://hooks.company.com/typosentinel",
				NotifyOnHigh:    true,
				NotifyOnMedium:  true,
				NotifyOnLow:     false,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(org)
}

// UpdateOrganizationSettings handles PUT /api/organizations/{id}/settings
func (s *Server) UpdateOrganizationSettings(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid organization ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user is admin of organization
	if user.OrganizationID != orgID || user.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var settings types.OrganizationSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// TODO: Validate and save settings to database

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// GetCustomRegistries handles GET /api/organizations/{id}/registries
func (s *Server) GetCustomRegistries(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid organization ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user belongs to organization
	if user.OrganizationID != orgID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// TODO: Get registries from database
	registries := []*types.CustomRegistry{
		{
			ID:       1,
			Name:     "Internal NPM",
			Type:     "npm",
			URL:      "https://npm.internal.company.com",
			Enabled:  true,
			Priority: 1,
			AuthType: "token",
		},
		{
			ID:       2,
			Name:     "JFrog Artifactory",
			Type:     "maven",
			URL:      "https://artifactory.company.com/maven",
			Enabled:  true,
			Priority: 2,
			AuthType: "basic",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(registries)
}

// CreateCustomRegistry handles POST /api/organizations/{id}/registries
func (s *Server) CreateCustomRegistry(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid organization ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user is admin of organization
	if user.OrganizationID != orgID || user.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var registry types.CustomRegistry
	if err := json.NewDecoder(r.Body).Decode(&registry); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate registry
	if err := s.validateCustomRegistry(&registry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Save to database
	registry.ID = 3 // Mock ID
	registry.OrganizationID = orgID

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(&registry)
}

// UpdateCustomRegistry handles PUT /api/organizations/{id}/registries/{registryId}
func (s *Server) UpdateCustomRegistry(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid organization ID", http.StatusBadRequest)
		return
	}

	registryID, err := strconv.Atoi(vars["registryId"])
	if err != nil {
		http.Error(w, "Invalid registry ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user is admin of organization
	if user.OrganizationID != orgID || user.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var registry types.CustomRegistry
	if err := json.NewDecoder(r.Body).Decode(&registry); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate registry
	if err := s.validateCustomRegistry(&registry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Update in database
	registry.ID = registryID
	registry.OrganizationID = orgID

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&registry)
}

// DeleteCustomRegistry handles DELETE /api/organizations/{id}/registries/{registryId}
func (s *Server) DeleteCustomRegistry(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid organization ID", http.StatusBadRequest)
		return
	}

	registryID, err := strconv.Atoi(vars["registryId"])
	if err != nil {
		http.Error(w, "Invalid registry ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user is admin of organization
	if user.OrganizationID != orgID || user.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// TODO: Delete from database
	_ = registryID // Use the registry ID

	w.WriteHeader(http.StatusNoContent)
}

// TestCustomRegistry handles POST /api/organizations/{id}/registries/{registryId}/test
func (s *Server) TestCustomRegistry(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid organization ID", http.StatusBadRequest)
		return
	}

	registryID, err := strconv.Atoi(vars["registryId"])
	if err != nil {
		http.Error(w, "Invalid registry ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user belongs to organization
	if user.OrganizationID != orgID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// TODO: Implement registry connection test
	_ = registryID // Use the registry ID

	result := map[string]interface{}{
		"status":      "success",
		"message":     "Registry connection successful",
		"response_time": "150ms",
		"packages_found": 1250,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// GetOrganizationStats handles GET /api/organizations/{id}/stats
func (s *Server) GetOrganizationStats(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid organization ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user belongs to organization
	if user.OrganizationID != orgID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// TODO: Get real stats from database
	stats := map[string]interface{}{
		"total_projects":     45,
		"total_packages":     1250,
		"threats_detected":   23,
		"scans_this_month":   156,
		"risk_distribution": map[string]int{
			"high":   5,
			"medium": 12,
			"low":    6,
			"none":   1227,
		},
		"top_threats": []map[string]interface{}{
			{
				"package": "suspicious-package",
				"type":    "typosquatting",
				"count":   8,
			},
			{
				"package": "malware-lib",
				"type":    "malware",
				"count":   3,
			},
		},
		"registry_usage": map[string]int{
			"npm":      850,
			"pypi":     300,
			"maven":    75,
			"internal": 25,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// validateCustomRegistry validates a custom registry configuration
func (s *Server) validateCustomRegistry(registry *types.CustomRegistry) error {
	if registry.Name == "" {
		return fmt.Errorf("registry name is required")
	}

	if registry.URL == "" {
		return fmt.Errorf("registry URL is required")
	}

	validTypes := []string{"npm", "pypi", "maven", "nuget", "gem", "cargo"}
	validType := false
	for _, validT := range validTypes {
		if registry.Type == validT {
			validType = true
			break
		}
	}
	if !validType {
		return fmt.Errorf("invalid registry type: %s", registry.Type)
	}

	validAuthTypes := []string{"none", "basic", "token", "oauth"}
	validAuthType := false
	for _, validA := range validAuthTypes {
		if registry.AuthType == validA {
			validAuthType = true
			break
		}
	}
	if !validAuthType {
		return fmt.Errorf("invalid auth type: %s", registry.AuthType)
	}

	return nil
}