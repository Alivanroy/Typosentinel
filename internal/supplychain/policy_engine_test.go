package supplychain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Alivanroy/Typosentinel/internal/edge"
	"github.com/Alivanroy/Typosentinel/internal/security"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestSupplyChainPolicyEngine(t *testing.T) {
	// Create mock dependencies
	config := edge.DefaultDIRTConfig()
	dirt := edge.NewDIRTAlgorithm(config)
	auditLogger, err := security.NewAuditLogger(&security.AuditLogConfig{
		LogPath:     "test-audit.log",
		EncryptLogs: false,
		MaxFileSize: 10 * 1024 * 1024,
		MaxFiles:    5,
		LogLevel:    "info",
	})
	require.NoError(t, err)

	t.Run("PolicyEngineCreation", func(t *testing.T) {
		engine := NewPolicyEngine(dirt, auditLogger)
		assert.NotNil(t, engine)
		assert.NotNil(t, engine.policies)
		assert.Equal(t, 5, len(engine.policies)) // 5 default policies
	})

	t.Run("DefaultPoliciesExist", func(t *testing.T) {
		engine := NewPolicyEngine(dirt, auditLogger)
		
		policyNames := []string{
			"Block Critical Risk Packages",
			"Alert on Typosquatting Detection",
			"Require Package Signatures",
			"Review Unmaintained Packages",
			"Block Critical Vulnerabilities",
		}
		
		for _, name := range policyNames {
			found := false
			for _, policy := range engine.policies {
				if policy.Name == name {
					found = true
					break
				}
			}
			assert.True(t, found, "Policy %s should exist", name)
		}
	})

	t.Run("EvaluatePolicyContext", func(t *testing.T) {
		engine := NewPolicyEngine(dirt, auditLogger)
		
		testCases := []struct {
			name           string
			context        SupplyChainPolicyContext
			expectedAction PolicyAction
			expectedPolicy string
		}{
			{
				name: "Critical Risk Package",
				context: SupplyChainPolicyContext{
					Package: &types.Package{
						Name:      "critical-risk-package",
						Version:   "1.0.0",
						Threats: []types.Threat{
							{
								ID:       "CVE-2023-1234",
								Package:  "critical-risk-package",
								Severity: types.SeverityCritical,
								Type:     types.ThreatTypeVulnerable,
							},
						},
						Metadata: &types.PackageMetadata{
							Downloads:   100,
							LastUpdated: &[]time.Time{time.Now().AddDate(0, -6, 0)}[0],
							Checksums:   map[string]string{"sha256": "abc123"}, // Add checksums to pass signature policy
						},
					},
					BusinessRisk:     0.95,
					AssetCriticality: edge.CriticalityCritical,
					IsDirect:         true,
					Timestamp:        time.Now(),
				},
				expectedAction: ActionBlock,
				expectedPolicy: "Block Critical Vulnerabilities",
			},
			{
				name: "Typosquatting Package",
				context: SupplyChainPolicyContext{
					Package: &types.Package{
						Name:      "reqeust", // Typosquatting attempt
						Version:   "2.88.2",
						Threats: []types.Threat{
							{
								ID:       "TYPO-001",
								Package:  "reqeust",
								Type:     types.ThreatTypeTyposquatting,
								Severity: types.SeverityHigh,
							},
						},
						Metadata: &types.PackageMetadata{
							Downloads:   50,
							LastUpdated: &[]time.Time{time.Now().AddDate(0, -3, 0)}[0],
						},
					},
					BusinessRisk:     0.8,
					AssetCriticality: edge.CriticalityInternal,
					IsDirect:         true,
					Timestamp:        time.Now(),
				},
				expectedAction: ActionAlert,
				expectedPolicy: "Alert on Typosquatting Detection",
			},
		}
		
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				results, err := engine.EvaluatePolicies(&tc.context)
				
				assert.NoError(t, err)
				assert.NotEmpty(t, results)
				
				// Find the most restrictive action
				var mostRestrictiveAction PolicyAction = ActionAllow
				var triggeringPolicy string
				for _, result := range results {
					if result.Triggered && tc.expectedAction == result.Action {
						mostRestrictiveAction = result.Action
						triggeringPolicy = result.PolicyName
						break
					}
				}
				
				assert.Equal(t, tc.expectedAction, mostRestrictiveAction)
				assert.Equal(t, tc.expectedPolicy, triggeringPolicy)
			})
		}
	})

	t.Run("AllowCompliantPackage", func(t *testing.T) {
		engine := NewPolicyEngine(dirt, auditLogger)
		
		context := SupplyChainPolicyContext{
			Package: &types.Package{
					Name:    "lodash",
					Version: "4.17.21",
					Threats: []types.Threat{},
					Metadata: &types.PackageMetadata{
						Downloads:   50000000,
						LastUpdated: &[]time.Time{time.Now().AddDate(0, -1, 0)}[0],
						Checksums:   map[string]string{"sha256": "abc123"}, // Add checksums
					},
				},
			BusinessRisk:     0.1,
			AssetCriticality: edge.CriticalityPublic,
			IsDirect:         true,
			Timestamp:        time.Now(),
		}
		
		results, err := engine.EvaluatePolicies(&context)
		
		assert.NoError(t, err)
		assert.NotEmpty(t, results)
		
		// Should allow compliant packages
		var hasBlockAction bool
		for _, result := range results {
			if result.Action == ActionBlock {
				hasBlockAction = true
				break
			}
		}
		assert.False(t, hasBlockAction, "Compliant package should not be blocked")
	})
}