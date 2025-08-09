package main

import (
	"context"
	"database/sql"
	"log"
	"log/slog"
	"os"
	"strconv"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/api/rest"
	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/internal/storage"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
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
	simpleLogger := &SimpleLogger{
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
	
	// Initialize proper logger for database components
	pkgLogger := logger.NewWithConfig(&logger.Config{
		Level:     logger.INFO,
		Format:    "text",
		Output:    os.Stdout,
		Timestamp: true,
		Caller:    true,
		Prefix:    "[TYPOSENTINEL]",
	})

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
	policyEngine := auth.NewPolicyEngine(simpleLogger)

	// Initialize authorization middleware
	authMiddleware := auth.NewAuthorizationMiddleware(rbacEngine, nil, true)

	// Initialize database connection (using SQLite for example)
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Initialize schema manager and create tables
	schemaManager := database.NewSchemaManager(db, pkgLogger)
	if err := schemaManager.Initialize(context.Background()); err != nil {
		log.Printf("Warning: Failed to initialize schema: %v", err)
	}

	// Create required tables manually for this example
	createPolicyViolationsSQL := `
		CREATE TABLE IF NOT EXISTS policy_violations (
			id TEXT PRIMARY KEY,
			policy_id TEXT NOT NULL,
			policy_name TEXT NOT NULL,
			severity TEXT NOT NULL,
			description TEXT NOT NULL,
			context TEXT,
			result TEXT,
			status TEXT NOT NULL DEFAULT 'open',
			approval_required BOOLEAN NOT NULL DEFAULT FALSE,
			approvals TEXT,
			remediation TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			resolved_at DATETIME,
			metadata TEXT
		);
	`
	if _, err := db.Exec(createPolicyViolationsSQL); err != nil {
		log.Printf("Warning: Failed to create policy_violations table: %v", err)
	}

	createAuditLogsSQL := `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			timestamp DATETIME NOT NULL,
			user_id TEXT,
			action TEXT NOT NULL,
			resource TEXT NOT NULL,
			source_ip TEXT,
			user_agent TEXT,
			severity TEXT NOT NULL,
			details TEXT,
			metadata TEXT
		);
	`
	if _, err := db.Exec(createAuditLogsSQL); err != nil {
		log.Printf("Warning: Failed to create audit_logs table: %v", err)
	}

	// Initialize violation store with proper database connection
	violationStore := storage.NewViolationStore(db, pkgLogger)

	// Initialize enterprise policy manager
	policyManager := auth.NewEnterprisePolicyManager(policyEngine, rbacEngine, violationStore, simpleLogger)

	// Initialize enterprise handlers
	enterpriseHandlers := rest.NewEnterpriseHandlers(policyManager, rbacEngine, authMiddleware, violationStore, simpleLogger)

	// Initialize ML pipeline (minimal setup)
	mlPipeline := &ml.MLPipeline{} // This would need proper initialization in real usage

	// Initialize analyzer (minimal setup)
	analyzer := &analyzer.Analyzer{} // This would need proper initialization in real usage

	// Get port from environment variable or use default
	port := 8080
	if portStr := os.Getenv("PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	// Configure REST API
	apiConfig := config.RESTAPIConfig{
		Enabled:  true,
		Host:     "localhost",
		Port:     port,
		BasePath: "/api",
		Versioning: config.APIVersioning{
			Enabled: true,
		},
	}

	// Create server with enterprise features
	server := rest.NewServerWithEnterprise(apiConfig, mlPipeline, analyzer, enterpriseHandlers)

	log.Println("Starting TypoSentinel server with enterprise features...")
	log.Println("Enterprise API endpoints available at:")
	log.Printf("  - Policy Management: http://localhost:%d/api/v1/enterprise/policies", port)
	log.Printf("  - RBAC Management: http://localhost:%d/api/v1/enterprise/rbac", port)
	log.Printf("  - Policy Enforcement: http://localhost:%d/api/v1/enterprise/enforcement", port)
	log.Printf("  - Approval Workflows: http://localhost:%d/api/v1/enterprise/approvals", port)

	// Start server
	if err := server.Start(context.Background()); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}