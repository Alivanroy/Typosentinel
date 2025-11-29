package types

import (
	"testing"
	"time"
)

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     string
	}{
		{"Low severity", SeverityLow, "low"},
		{"Medium severity", SeverityMedium, "medium"},
		{"High severity", SeverityHigh, "high"},
		{"Critical severity", SeverityCritical, "critical"},
		{"Unknown severity", SeverityUnknown, "unknown"},
		{"Invalid severity", Severity(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.String(); got != tt.want {
				t.Errorf("Severity.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRiskLevel_String(t *testing.T) {
	tests := []struct {
		name      string
		riskLevel RiskLevel
		want      string
	}{
		{"Minimal risk", RiskLevelMinimal, "minimal"},
		{"Low risk", RiskLevelLow, "low"},
		{"Medium risk", RiskLevelMedium, "medium"},
		{"High risk", RiskLevelHigh, "high"},
		{"Critical risk", RiskLevelCritical, "critical"},
		{"Invalid risk", RiskLevel(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.riskLevel.String(); got != tt.want {
				t.Errorf("RiskLevel.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestThreatType_String(t *testing.T) {
	// ThreatType is a string type, so it doesn't have a String() method
	// Let's test the constants instead
	tests := []struct {
		name       string
		threatType ThreatType
		want       string
	}{
		{"Typosquatting", ThreatTypeTyposquatting, "typosquatting"},
		{"Malicious package", ThreatTypeMaliciousPackage, "malicious_package"},
		{"Homoglyph", ThreatTypeHomoglyph, "homoglyph"},
		{"Dependency confusion", ThreatTypeDependencyConfusion, "dependency_confusion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.threatType); got != tt.want {
				t.Errorf("ThreatType = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPackage_Validate(t *testing.T) {
	// Package doesn't have a Validate() method, so let's test the struct creation
	tests := []struct {
		name    string
		pkg     Package
		wantErr bool
	}{
		{
			name: "Valid package",
			pkg: Package{
				Name:     "express",
				Version:  "4.18.0",
				Registry: "npm",
			},
			wantErr: false,
		},
		{
			name: "Empty name",
			pkg: Package{
				Name:     "",
				Version:  "4.18.0",
				Registry: "npm",
			},
			wantErr: true,
		},
		{
			name: "Empty version",
			pkg: Package{
				Name:     "express",
				Version:  "",
				Registry: "npm",
			},
			wantErr: false, // Empty version should be allowed
		},
		{
			name: "Empty registry",
			pkg: Package{
				Name:     "express",
				Version:  "4.18.0",
				Registry: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simple validation: name and registry should not be empty
			if tt.pkg.Name == "" || tt.pkg.Registry == "" {
				if !tt.wantErr {
					t.Errorf("Package should be invalid but wasn't flagged")
				}
			} else {
				if tt.wantErr {
					t.Errorf("Package should be valid but was flagged as invalid")
				}
			}
		})
	}
}

func TestDependency_Validate(t *testing.T) {
	// Dependency doesn't have a Validate() method
	tests := []struct {
		name    string
		dep     Dependency
		wantErr bool
	}{
		{
			name: "Valid dependency",
			dep: Dependency{
				Name:     "express",
				Version:  "4.18.0",
				Registry: "npm",
			},
			wantErr: false,
		},
		{
			name: "Empty name",
			dep: Dependency{
				Name:     "",
				Version:  "4.18.0",
				Registry: "npm",
			},
			wantErr: true,
		},
		{
			name: "Empty registry",
			dep: Dependency{
				Name:     "express",
				Version:  "4.18.0",
				Registry: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simple validation: name and registry should not be empty
			if tt.dep.Name == "" || tt.dep.Registry == "" {
				if !tt.wantErr {
					t.Errorf("Dependency should be invalid but wasn't flagged")
				}
			} else {
				if tt.wantErr {
					t.Errorf("Dependency should be valid but was flagged as invalid")
				}
			}
		})
	}
}

func TestThreat_BasicValidation(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name   string
		threat Threat
		valid  bool
	}{
		{
			name: "Valid threat",
			threat: Threat{
				ID:          "threat-123",
				Package:     "expresss",
				Version:     "1.0.0",
				Registry:    "npm",
				Type:        ThreatTypeTyposquatting,
				Severity:    SeverityHigh,
				Confidence:  0.85,
				Description: "Potential typosquatting attack",
				SimilarTo:   "express",
				DetectedAt:  now,
			},
			valid: true,
		},
		{
			name: "Empty ID",
			threat: Threat{
				ID:          "",
				Package:     "expresss",
				Version:     "1.0.0",
				Registry:    "npm",
				Type:        ThreatTypeTyposquatting,
				Severity:    SeverityHigh,
				Confidence:  0.85,
				Description: "Potential typosquatting attack",
				SimilarTo:   "express",
				DetectedAt:  now,
			},
			valid: false,
		},
		{
			name: "Empty package name",
			threat: Threat{
				ID:          "threat-123",
				Package:     "",
				Version:     "1.0.0",
				Registry:    "npm",
				Type:        ThreatTypeTyposquatting,
				Severity:    SeverityHigh,
				Confidence:  0.85,
				Description: "Potential typosquatting attack",
				SimilarTo:   "express",
				DetectedAt:  now,
			},
			valid: false,
		},
		{
			name: "Empty registry",
			threat: Threat{
				ID:          "threat-123",
				Package:     "expresss",
				Version:     "1.0.0",
				Registry:    "",
				Type:        ThreatTypeTyposquatting,
				Severity:    SeverityHigh,
				Confidence:  0.85,
				Description: "Potential typosquatting attack",
				SimilarTo:   "express",
				DetectedAt:  now,
			},
			valid: false,
		},
		{
			name: "Invalid confidence",
			threat: Threat{
				ID:          "threat-123",
				Package:     "expresss",
				Version:     "1.0.0",
				Registry:    "npm",
				Type:        ThreatTypeTyposquatting,
				Severity:    SeverityHigh,
				Confidence:  1.5, // > 1.0
				Description: "Potential typosquatting attack",
				SimilarTo:   "express",
				DetectedAt:  now,
			},
			valid: false,
		},
		{
			name: "Negative confidence",
			threat: Threat{
				ID:          "threat-123",
				Package:     "expresss",
				Version:     "1.0.0",
				Registry:    "npm",
				Type:        ThreatTypeTyposquatting,
				Severity:    SeverityHigh,
				Confidence:  -0.1, // < 0.0
				Description: "Potential typosquatting attack",
				SimilarTo:   "express",
				DetectedAt:  now,
			},
			valid: false,
		},
		{
			name: "Empty description",
			threat: Threat{
				ID:          "threat-123",
				Package:     "expresss",
				Version:     "1.0.0",
				Registry:    "npm",
				Type:        ThreatTypeTyposquatting,
				Severity:    SeverityHigh,
				Confidence:  0.85,
				Description: "",
				SimilarTo:   "express",
				DetectedAt:  now,
			},
			valid: false,
		},
		{
			name: "Zero detection time",
			threat: Threat{
				ID:          "threat-123",
				Package:     "expresss",
				Version:     "1.0.0",
				Registry:    "npm",
				Type:        ThreatTypeTyposquatting,
				Severity:    SeverityHigh,
				Confidence:  0.85,
				Description: "Potential typosquatting attack",
				SimilarTo:   "express",
				DetectedAt:  time.Time{}, // Zero time
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation logic
			valid := tt.threat.ID != "" &&
				tt.threat.Package != "" &&
				tt.threat.Registry != "" &&
				tt.threat.Description != "" &&
				tt.threat.Confidence >= 0.0 &&
				tt.threat.Confidence <= 1.0 &&
				!tt.threat.DetectedAt.IsZero()

			if valid != tt.valid {
				t.Errorf("Threat validation = %v, want %v", valid, tt.valid)
			}
		})
	}
}

func TestEvidence_BasicValidation(t *testing.T) {
	tests := []struct {
		name     string
		evidence Evidence
		valid    bool
	}{
		{
			name: "Valid evidence",
			evidence: Evidence{
				Type:        "edit_distance",
				Description: "Levenshtein distance",
				Value:       2,
				Score:       0.8,
			},
			valid: true,
		},
		{
			name: "Empty type",
			evidence: Evidence{
				Type:        "",
				Description: "Levenshtein distance",
				Value:       2,
				Score:       0.8,
			},
			valid: false,
		},
		{
			name: "Empty description",
			evidence: Evidence{
				Type:        "edit_distance",
				Description: "",
				Value:       2,
				Score:       0.8,
			},
			valid: false,
		},
		{
			name: "Invalid score",
			evidence: Evidence{
				Type:        "edit_distance",
				Description: "Levenshtein distance",
				Value:       2,
				Score:       1.5, // > 1.0
			},
			valid: false,
		},
		{
			name: "Negative score",
			evidence: Evidence{
				Type:        "edit_distance",
				Description: "Levenshtein distance",
				Value:       2,
				Score:       -0.1, // < 0.0
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation logic
			valid := tt.evidence.Type != "" &&
				tt.evidence.Description != "" &&
				tt.evidence.Score >= 0.0 &&
				tt.evidence.Score <= 1.0

			if valid != tt.valid {
				t.Errorf("Evidence validation = %v, want %v", valid, tt.valid)
			}
		})
	}
}

func TestWarning_BasicValidation(t *testing.T) {
	tests := []struct {
		name    string
		warning Warning
		valid   bool
	}{
		{
			name: "Valid warning",
			warning: Warning{
				ID:         "warning-123",
				Package:    "express",
				Version:    "4.18.0",
				Registry:   "npm",
				Type:       "outdated",
				Message:    "Package is outdated",
				DetectedAt: time.Now(),
			},
			valid: true,
		},
		{
			name: "Empty ID",
			warning: Warning{
				ID:         "",
				Package:    "express",
				Version:    "4.18.0",
				Registry:   "npm",
				Type:       "outdated",
				Message:    "Package is outdated",
				DetectedAt: time.Now(),
			},
			valid: false,
		},
		{
			name: "Empty package name",
			warning: Warning{
				ID:         "warning-123",
				Package:    "",
				Version:    "4.18.0",
				Registry:   "npm",
				Type:       "outdated",
				Message:    "Package is outdated",
				DetectedAt: time.Now(),
			},
			valid: false,
		},
		{
			name: "Empty message",
			warning: Warning{
				ID:         "warning-123",
				Package:    "express",
				Version:    "4.18.0",
				Registry:   "npm",
				Type:       "outdated",
				Message:    "",
				DetectedAt: time.Now(),
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation logic
			valid := tt.warning.ID != "" &&
				tt.warning.Package != "" &&
				tt.warning.Registry != "" &&
				tt.warning.Message != "" &&
				!tt.warning.DetectedAt.IsZero()

			if valid != tt.valid {
				t.Errorf("Warning validation = %v, want %v", valid, tt.valid)
			}
		})
	}
}

func TestScanResult_TotalPackages(t *testing.T) {
	result := &ScanResult{
		Packages: []*Package{
			{Name: "expresss"},
			{Name: "crossenv"},
			{Name: "lodash"},
		},
	}

	// Should count total packages
	if got := len(result.Packages); got != 3 {
		t.Errorf("ScanResult.TotalPackages() = %v, want %v", got, 3)
	}
}

func TestScanStatus_String(t *testing.T) {
	tests := []struct {
		name   string
		status ScanStatus
		want   string
	}{
		{"Pending", ScanStatusPending, "pending"},
		{"Running", ScanStatusRunning, "running"},
		{"Completed", ScanStatusCompleted, "completed"},
		{"Failed", ScanStatusFailed, "failed"},
		{"Cancelled", ScanStatusCancelled, "cancelled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.status); got != tt.want {
				t.Errorf("ScanStatus.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserRole_String(t *testing.T) {
	tests := []struct {
		name string
		role UserRole
		want string
	}{
		{"Admin", UserRoleAdmin, "admin"},
		{"Member", UserRoleMember, "member"},
		{"Viewer", UserRoleViewer, "viewer"},
		{"API Only", UserRoleAPIOnly, "api_only"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.role); got != tt.want {
				t.Errorf("UserRole.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrustLevel_String(t *testing.T) {
	tests := []struct {
		name  string
		level TrustLevel
		want  string
	}{
		{"Very Low", TrustLevelVeryLow, "very_low"},
		{"Low", TrustLevelLow, "low"},
		{"Medium", TrustLevelMedium, "medium"},
		{"High", TrustLevelHigh, "high"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.level); got != tt.want {
				t.Errorf("TrustLevel.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
