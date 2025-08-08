package main

import (
	"context"
	"log"
	"log/slog"
	"os"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/api/rest"
	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/internal/storage"
)

// Logger interface implementation for enterprise components
type SimpleLogger struct {
	logger *slog.Logger
}

func (l *SimpleLogger) Debug(msg string, args ...interface{}) {
	l.logger.Debug(msg, args...)
}

func (l *SimpleLogger) Info(msg string, args ...interface{}) {
	l.logger.Info(msg, args...)
}

func (l *SimpleLogger) Warn(msg string, args ...interface{}) {
	l.logger.Warn(msg, args...)
}

func (l *SimpleLogger) Error(msg string, args ...interface{}) {
	l.logger.Error(msg, args...)
}

func main() {
	// Initialize logger
	logger := &SimpleLogger{
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	// Initialize RBAC engine with minimal config
	rbacEngine := auth.NewRBACEngine(nil)

	// Add some default roles
	adminRole := &auth.Role{
		Name:        "admin",
		Description: "Administrator with full access",
		Permissions: []auth.Permission{
			auth.Permission("policies:read"),
			auth.Permission("policies:create"),
			auth.Permission("policies:update"),
			auth.Permission("policies:delete"),
			auth.Permission("rbac:read"),
			auth.Permission("rbac:create"),
			auth.Permission("rbac:update"),
			auth.Permission("rbac:delete"),
			auth.Permission("enforcement:read"),
			auth.Permission("enforcement:update"),
			auth.Permission("approvals:read"),
			auth.Permission("approvals:approve"),
		},
	}
	rbacEngine.AddRole(adminRole)

	analystRole := &auth.Role{
		Name:        "security_analyst",
		Description: "Security analyst with read access",
		Permissions: []auth.Permission{
			auth.Permission("policies:read"),
			auth.Permission("rbac:read"),
			auth.Permission("enforcement:read"),
			auth.Permission("approvals:read"),
		},
	}
	rbacEngine.AddRole(analystRole)

	// Initialize policy engine
	policyEngine := auth.NewPolicyEngine(logger)

	// Initialize enterprise policy manager
	policyManager := auth.NewEnterprisePolicyManager(policyEngine, rbacEngine, logger)

	// Initialize authorization middleware
	authMiddleware := auth.NewAuthorizationMiddleware(rbacEngine, nil, true)

	// Initialize violation store (minimal setup for example)
	violationStore := &storage.ViolationStore{} // This would need proper initialization in real usage

	// Initialize enterprise handlers
	enterpriseHandlers := rest.NewEnterpriseHandlers(policyManager, rbacEngine, authMiddleware, violationStore, logger)

	// Initialize ML pipeline (minimal setup)
	mlPipeline := &ml.MLPipeline{} // This would need proper initialization in real usage

	// Initialize analyzer (minimal setup)
	analyzer := &analyzer.Analyzer{} // This would need proper initialization in real usage

	// Configure REST API
	apiConfig := config.RESTAPIConfig{
		Enabled:  true,
		Host:     "localhost",
		Port:     8080,
		BasePath: "/api",
		Versioning: config.APIVersioning{
			Enabled: true,
		},
	}

	// Create server with enterprise features
	server := rest.NewServerWithEnterprise(apiConfig, mlPipeline, analyzer, enterpriseHandlers)

	log.Println("Starting TypoSentinel server with enterprise features...")
	log.Println("Enterprise API endpoints available at:")
	log.Println("  - Policy Management: http://localhost:8080/api/v1/enterprise/policies")
	log.Println("  - RBAC Management: http://localhost:8080/api/v1/enterprise/rbac")
	log.Println("  - Policy Enforcement: http://localhost:8080/api/v1/enterprise/enforcement")
	log.Println("  - Approval Workflows: http://localhost:8080/api/v1/enterprise/approvals")

	// Start server
	if err := server.Start(context.Background()); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}