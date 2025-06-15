package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/typosentinel/typosentinel/internal/scanner"
	"github.com/typosentinel/typosentinel/pkg/types"
)

// GetProjects handles GET /api/projects
func (s *Server) GetProjects(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// TODO: Get projects from database filtered by organization
	projects := []*types.ProjectScan{
		{
			ID:             1,
			Name:           "Frontend App",
			Path:           "/projects/frontend-app",
			Type:           "nodejs",
			OrganizationID: user.OrganizationID,
			LastScan: &types.ScanResult{
				ID:        "scan_123",
				Status:    "completed",
				CreatedAt: time.Now().Add(-2 * time.Hour),
				Summary: &types.ScanSummary{
					TotalPackages: 45,
					ThreatsFound:  3,
					RiskDistribution: map[string]int{
						"high":   1,
						"medium": 2,
						"low":    0,
						"none":   42,
					},
				},
			},
			AutoScan:  true,
			CreatedAt: time.Now().Add(-7 * 24 * time.Hour),
			UpdatedAt: time.Now().Add(-2 * time.Hour),
		},
		{
			ID:             2,
			Name:           "Backend API",
			Path:           "/projects/backend-api",
			Type:           "python",
			OrganizationID: user.OrganizationID,
			LastScan: &types.ScanResult{
				ID:        "scan_124",
				Status:    "completed",
				CreatedAt: time.Now().Add(-1 * time.Hour),
				Summary: &types.ScanSummary{
					TotalPackages: 28,
					ThreatsFound:  0,
					RiskDistribution: map[string]int{
						"high":   0,
						"medium": 0,
						"low":    0,
						"none":   28,
					},
				},
			},
			AutoScan:  false,
			CreatedAt: time.Now().Add(-14 * 24 * time.Hour),
			UpdatedAt: time.Now().Add(-1 * time.Hour),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(projects)
}

// CreateProject handles POST /api/projects
func (s *Server) CreateProject(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Name     string `json:"name"`
		Path     string `json:"path"`
		AutoScan bool   `json:"auto_scan"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Path == "" {
		http.Error(w, "Name and path are required", http.StatusBadRequest)
		return
	}

	// Detect project type
	scanner := scanner.New(s.config)
	projectInfo, err := scanner.ScanProject(req.Path)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to detect project: %v", err), http.StatusBadRequest)
		return
	}

	// TODO: Save to database
	project := &types.ProjectScan{
		ID:             3, // Mock ID
		Name:           req.Name,
		Path:           req.Path,
		Type:           projectInfo.Type,
		OrganizationID: user.OrganizationID,
		AutoScan:       req.AutoScan,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(project)
}

// GetProject handles GET /api/projects/{id}
func (s *Server) GetProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// TODO: Get project from database and verify organization access
	project := &types.ProjectScan{
		ID:             projectID,
		Name:           "Frontend App",
		Path:           "/projects/frontend-app",
		Type:           "nodejs",
		OrganizationID: user.OrganizationID,
		AutoScan:       true,
		CreatedAt:      time.Now().Add(-7 * 24 * time.Hour),
		UpdatedAt:      time.Now().Add(-2 * time.Hour),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// UpdateProject handles PUT /api/projects/{id}
func (s *Server) UpdateProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Name     string `json:"name"`
		Path     string `json:"path"`
		AutoScan bool   `json:"auto_scan"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// TODO: Update project in database
	project := &types.ProjectScan{
		ID:             projectID,
		Name:           req.Name,
		Path:           req.Path,
		OrganizationID: user.OrganizationID,
		AutoScan:       req.AutoScan,
		UpdatedAt:      time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// DeleteProject handles DELETE /api/projects/{id}
func (s *Server) DeleteProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// TODO: Delete project from database (verify organization access)
	_ = projectID
	_ = user

	w.WriteHeader(http.StatusNoContent)
}

// ScanProject handles POST /api/projects/{id}/scan
func (s *Server) ScanProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// TODO: Get project from database and verify access
	// TODO: Use user.OrganizationID to filter projects
	_ = user // Temporary to avoid unused variable error
	projectPath := "/projects/frontend-app" // Mock path

	// Perform scan
	scanner := scanner.New(s.config)
	result, err := scanner.ScanProject(projectPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Scan failed: %v", err), http.StatusInternalServerError)
		return
	}

	// TODO: Save scan result to database
	result.ProjectID = projectID

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(result)
}

// GetProjectScans handles GET /api/projects/{id}/scans
func (s *Server) GetProjectScans(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// TODO: Get scans from database
	scans := []*types.ScanResult{
		{
			ID:        "scan_123",
			ProjectID: projectID,
			Target:    "/projects/frontend-app",
			Type:      "nodejs",
			Status:    "completed",
			Summary: &types.ScanSummary{
				TotalPackages: 45,
				ThreatsFound:  3,
				RiskDistribution: map[string]int{
					"high":   1,
					"medium": 2,
					"low":    0,
					"none":   42,
				},
			},
			Duration:  2 * time.Minute,
			CreatedAt: time.Now().Add(-2 * time.Hour),
		},
		{
			ID:        "scan_122",
			ProjectID: projectID,
			Target:    "/projects/frontend-app",
			Type:      "nodejs",
			Status:    "completed",
			Summary: &types.ScanSummary{
				TotalPackages: 43,
				ThreatsFound:  2,
				RiskDistribution: map[string]int{
					"high":   0,
					"medium": 2,
					"low":    0,
					"none":   41,
				},
			},
			Duration:  1*time.Minute + 45*time.Second,
			CreatedAt: time.Now().Add(-24 * time.Hour),
		},
	}

	_ = user // Use user for access control

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

// GetProjectDependencyTree handles GET /api/projects/{id}/dependencies
func (s *Server) GetProjectDependencyTree(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// TODO: Get project from database and verify access
	projectPath := "/projects/frontend-app" // Mock path

	// Build dependency tree
	scanner := scanner.New(s.config)
	tree, err := scanner.BuildDependencyTree(projectPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to build dependency tree: %v", err), http.StatusInternalServerError)
		return
	}

	_ = projectID
	_ = user

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tree)
}

// GetProjectStats handles GET /api/projects/{id}/stats
func (s *Server) GetProjectStats(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}

	// Get user from context
	user, ok := r.Context().Value("user").(*types.User)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// TODO: Get real stats from database
	stats := map[string]interface{}{
		"total_scans":        15,
		"total_packages":     45,
		"threats_detected":   3,
		"last_scan":          time.Now().Add(-2 * time.Hour),
		"risk_distribution": map[string]int{
			"high":   1,
			"medium": 2,
			"low":    0,
			"none":   42,
		},
		"scan_history": []map[string]interface{}{
			{
				"date":    time.Now().Add(-24 * time.Hour).Format("2006-01-02"),
				"threats": 2,
			},
			{
				"date":    time.Now().Add(-48 * time.Hour).Format("2006-01-02"),
				"threats": 1,
			},
			{
				"date":    time.Now().Add(-72 * time.Hour).Format("2006-01-02"),
				"threats": 3,
			},
		},
		"package_types": map[string]int{
			"production":  35,
			"development": 10,
		},
	}

	_ = projectID
	_ = user

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// AutoScanProjects handles automatic scanning of projects
func (s *Server) AutoScanProjects() {
	// TODO: Implement automatic scanning logic
	// This would typically:
	// 1. Get all projects with auto_scan enabled
	// 2. Check if they need scanning based on schedule
	// 3. Perform scans and save results
	// 4. Send notifications if threats are found
}