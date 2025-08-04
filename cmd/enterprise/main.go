package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/api/rest"
	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/internal/enterprise/audit"
	"github.com/Alivanroy/Typosentinel/internal/enterprise/dashboard"
	"github.com/Alivanroy/Typosentinel/internal/events"
	"github.com/Alivanroy/Typosentinel/internal/integrations/hub"
	"github.com/Alivanroy/Typosentinel/internal/interfaces"
	"github.com/Alivanroy/Typosentinel/internal/logging"
	"github.com/Alivanroy/Typosentinel/internal/monitoring"
	"github.com/Alivanroy/Typosentinel/internal/orchestrator"
	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/Alivanroy/Typosentinel/internal/repository/connectors"
	pkglogger "github.com/Alivanroy/Typosentinel/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	configFile string
	verbose    bool
	logLevel   string
	startTime  time.Time
)

// LoggerAdapter adapts logging.Logger to interfaces.Logger interface
type LoggerAdapter struct {
	logger *logging.Logger
}

func (la *LoggerAdapter) Debug(msg string, fields ...interfaces.LogField) {
	la.logger.Debug(msg, fields...)
}

func (la *LoggerAdapter) Info(msg string, fields ...interfaces.LogField) {
	la.logger.Info(msg, fields...)
}

func (la *LoggerAdapter) Warn(msg string, fields ...interfaces.LogField) {
	la.logger.Warn(msg, fields...)
}

func (la *LoggerAdapter) Error(msg string, fields ...interfaces.LogField) {
	la.logger.Error(msg, fields...)
}

func (la *LoggerAdapter) Fatal(msg string, fields ...interfaces.LogField) {
	la.logger.Fatal(msg, fields...)
}

func (la *LoggerAdapter) WithContext(ctx context.Context) interfaces.Logger {
	return &LoggerAdapter{logger: la.logger.WithContext(ctx).(*logging.Logger)}
}

func (la *LoggerAdapter) WithFields(fields ...interfaces.LogField) interfaces.Logger {
	return &LoggerAdapter{logger: la.logger.WithFields(fields...).(*logging.Logger)}
}

// AuthLoggerAdapter adapts logging.Logger to auth.Logger interface
type AuthLoggerAdapter struct {
	logger *logging.Logger
}

func (ala *AuthLoggerAdapter) Debug(msg string, fields ...interface{}) {
	// Convert interface{} fields to LogField
	logFields := make([]interfaces.LogField, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			logFields = append(logFields, interfaces.NewField(key, fields[i+1]))
		}
	}
	ala.logger.Debug(msg, logFields...)
}

func (ala *AuthLoggerAdapter) Info(msg string, fields ...interface{}) {
	logFields := make([]interfaces.LogField, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			logFields = append(logFields, interfaces.NewField(key, fields[i+1]))
		}
	}
	ala.logger.Info(msg, logFields...)
}

func (ala *AuthLoggerAdapter) Warn(msg string, fields ...interface{}) {
	logFields := make([]interfaces.LogField, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			logFields = append(logFields, interfaces.NewField(key, fields[i+1]))
		}
	}
	ala.logger.Warn(msg, logFields...)
}

func (ala *AuthLoggerAdapter) Error(msg string, fields ...interface{}) {
	logFields := make([]interfaces.LogField, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			logFields = append(logFields, interfaces.NewField(key, fields[i+1]))
		}
	}
	ala.logger.Error(msg, logFields...)
}

// PkgLoggerAdapter adapts logging.Logger to pkg/logger.Logger interface
type PkgLoggerAdapter struct {
	logger *logging.Logger
}

func (pla *PkgLoggerAdapter) Info(msg string, fields ...map[string]interface{}) {
	// Convert map fields to LogField
	logFields := make([]interfaces.LogField, 0)
	for _, fieldMap := range fields {
		for key, value := range fieldMap {
			logFields = append(logFields, interfaces.NewField(key, value))
		}
	}
	pla.logger.Info(msg, logFields...)
}

func (pla *PkgLoggerAdapter) Error(msg string, fields ...map[string]interface{}) {
	logFields := make([]interfaces.LogField, 0)
	for _, fieldMap := range fields {
		for key, value := range fieldMap {
			logFields = append(logFields, interfaces.NewField(key, value))
		}
	}
	pla.logger.Error(msg, logFields...)
}

func (pla *PkgLoggerAdapter) Debug(msg string, fields ...map[string]interface{}) {
	logFields := make([]interfaces.LogField, 0)
	for _, fieldMap := range fields {
		for key, value := range fieldMap {
			logFields = append(logFields, interfaces.NewField(key, value))
		}
	}
	pla.logger.Debug(msg, logFields...)
}

// Helper functions
func outputScanResult(result *repository.ScanResult) error {
	if result == nil {
		fmt.Println("No scan results to output")
		return nil
	}

	fmt.Printf("Scan completed successfully!\n")
	fmt.Printf("Repository: %s\n", result.Repository.FullName)
	fmt.Printf("Scan ID: %s\n", result.ScanID)
	fmt.Printf("Status: %s\n", result.Status)
	fmt.Printf("Duration: %v\n", result.Duration)
	fmt.Printf("Dependency Files: %d\n", len(result.DependencyFiles))

	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
	}

	if result.Message != "" {
		fmt.Printf("Message: %s\n", result.Message)
	}

	return nil
}

func initializeGitHubConnector(cfg *config.Config) (repository.Connector, error) {
	factory := connectors.NewFactory()
	
	// Get GitHub token from environment variable
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable is required")
	}
	
	platformConfig := repository.PlatformConfig{
		BaseURL: "https://api.github.com",
		Auth: repository.AuthConfig{
			Type:  "token",
			Token: token,
		},
		Timeout: 30 * time.Second,
	}
	
	connector, err := factory.CreateConnector("github", platformConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub connector: %w", err)
	}
	
	return connector, nil
}

func initializeGitLabConnector(cfg *config.Config) (repository.Connector, error) {
	factory := connectors.NewFactory()
	
	// Get GitLab token from environment
	gitlabToken := os.Getenv("GITLAB_TOKEN")
	if gitlabToken == "" {
		return nil, fmt.Errorf("GITLAB_TOKEN environment variable is required")
	}
	
	// Get GitLab URL (default to gitlab.com)
	gitlabURL := os.Getenv("GITLAB_URL")
	if gitlabURL == "" {
		gitlabURL = "https://gitlab.com/api/v4"
	}
	
	// Create platform config
	platformConfig := repository.PlatformConfig{
		BaseURL: gitlabURL,
		Auth: repository.AuthConfig{
			Type:  "token",
			Token: gitlabToken,
		},
		Timeout: 30 * time.Second,
	}
	
	// Create GitLab connector
	return factory.CreateConnector("gitlab", platformConfig)
}

func initializeBitbucketConnector(cfg *config.Config) (repository.Connector, error) {
	factory := connectors.NewFactory()
	
	// Get Bitbucket credentials from environment
	bitbucketUsername := os.Getenv("BITBUCKET_USERNAME")
	bitbucketPassword := os.Getenv("BITBUCKET_APP_PASSWORD")
	if bitbucketUsername == "" || bitbucketPassword == "" {
		return nil, fmt.Errorf("BITBUCKET_USERNAME and BITBUCKET_APP_PASSWORD environment variables are required")
	}
	
	// Create platform config
	platformConfig := repository.PlatformConfig{
		BaseURL: "https://api.bitbucket.org/2.0",
		Auth: repository.AuthConfig{
			Type:     "basic",
			Username: bitbucketUsername,
			Password: bitbucketPassword,
		},
		Timeout: 30 * time.Second,
	}
	
	// Create Bitbucket connector
	return factory.CreateConnector("bitbucket", platformConfig)
}

func initializeAzureDevOpsConnector(cfg *config.Config) (repository.Connector, error) {
	factory := connectors.NewFactory()
	
	// Get Azure DevOps credentials from environment
	azureToken := os.Getenv("AZURE_DEVOPS_TOKEN")
	azureOrg := os.Getenv("AZURE_DEVOPS_ORG")
	if azureToken == "" || azureOrg == "" {
		return nil, fmt.Errorf("AZURE_DEVOPS_TOKEN and AZURE_DEVOPS_ORG environment variables are required")
	}
	
	// Create platform config
	platformConfig := repository.PlatformConfig{
		BaseURL: fmt.Sprintf("https://dev.azure.com/%s", azureOrg),
		Auth: repository.AuthConfig{
			Type:  "token",
			Token: azureToken,
		},
		Timeout: 30 * time.Second,
	}
	
	// Create Azure DevOps connector
	return factory.CreateConnector("azuredevops", platformConfig)
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "typosentinel-enterprise",
		Short: "TypoSentinel Enterprise - Advanced repository security scanning platform",
		Long: `TypoSentinel Enterprise provides comprehensive security scanning capabilities
for enterprise environments with advanced features including:

- Multi-platform repository scanning (GitHub, GitLab, Bitbucket, Azure DevOps)
- Scheduled scanning with enterprise policies
- Advanced threat detection and ML-powered analysis
- Comprehensive audit logging and compliance reporting
- Real-time monitoring and alerting
- Enterprise authentication and authorization (LDAP, SSO, RBAC)
- Integration with SIEM systems and security tools
- Centralized dashboard and reporting`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			initConfig()
		},
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.typosentinel-enterprise.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")

	// Add subcommands
	rootCmd.AddCommand(serverCmd())
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(scheduleCmd())
	rootCmd.AddCommand(auditCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(healthCmd())
	rootCmd.AddCommand(exportCmd())
	rootCmd.AddCommand(userCmd())
	rootCmd.AddCommand(policyCmd())
	rootCmd.AddCommand(integrationCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the TypoSentinel Enterprise server",
		Long:  "Start the TypoSentinel Enterprise server with web UI, API, and background services",
		Run:   runServer,
	}

	cmd.Flags().String("bind", "0.0.0.0:8080", "Address to bind the server to")
	cmd.Flags().Bool("enable-ui", true, "Enable web UI")
	cmd.Flags().Bool("enable-api", true, "Enable REST API")
	cmd.Flags().Bool("enable-scheduler", true, "Enable scan scheduler")
	cmd.Flags().Bool("enable-monitoring", true, "Enable monitoring and health checks")
	cmd.Flags().Bool("enable-audit", true, "Enable audit logging")

	return cmd
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scanning operations",
		Long:  "Perform various scanning operations on repositories and organizations",
	}

	// Scan single repository
	scanSingleCmd := &cobra.Command{
		Use:   "repository [platform] [owner/repo]",
		Short: "Scan a single repository",
		Args:  cobra.ExactArgs(2),
		Run:   runScanRepository,
	}
	scanSingleCmd.Flags().String("branch", "", "Specific branch to scan")
	scanSingleCmd.Flags().String("output", "futuristic", "Output format (futuristic, table, json, sarif, cyclonedx)")
	scanSingleCmd.Flags().String("output-file", "", "Output file path")
	scanSingleCmd.Flags().Bool("include-dev", false, "Include development dependencies")

	// Scan organization
	scanOrgCmd := &cobra.Command{
		Use:   "organization [platform] [org]",
		Short: "Scan all repositories in an organization",
		Args:  cobra.ExactArgs(2),
		Run:   runScanOrganization,
	}
	scanOrgCmd.Flags().Int("max-repos", 100, "Maximum number of repositories to scan")
	scanOrgCmd.Flags().Bool("include-private", false, "Include private repositories")
	scanOrgCmd.Flags().Bool("include-forks", false, "Include forked repositories")
	scanOrgCmd.Flags().Bool("include-archived", false, "Include archived repositories")
	scanOrgCmd.Flags().StringSlice("languages", nil, "Filter by programming languages")
	scanOrgCmd.Flags().String("output", "futuristic", "Output format (futuristic, table, json, sarif, cyclonedx)")
	scanOrgCmd.Flags().String("report-file", "", "Generate consolidated report file")

	// Scan from config
	scanConfigCmd := &cobra.Command{
		Use:   "config [config-file]",
		Short: "Scan repositories defined in configuration file",
		Args:  cobra.ExactArgs(1),
		Run:   runScanConfig,
	}

	cmd.AddCommand(scanSingleCmd)
	cmd.AddCommand(scanOrgCmd)
	cmd.AddCommand(scanConfigCmd)

	return cmd
}

func scheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage scheduled scans",
		Long:  "Create, update, delete, and manage scheduled scanning operations",
	}

	// List schedules
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all scheduled scans",
		Run:   runScheduleList,
	}

	// Create schedule
	createCmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new scheduled scan",
		Args:  cobra.ExactArgs(1),
		Run:   runScheduleCreate,
	}
	createCmd.Flags().String("cron", "", "Cron expression for schedule (required)")
	createCmd.Flags().String("description", "", "Description of the scheduled scan")
	createCmd.Flags().String("config", "", "Configuration file for scan targets")
	createCmd.Flags().Bool("enabled", true, "Enable the schedule immediately")
	createCmd.MarkFlagRequired("cron")

	// Update schedule
	updateCmd := &cobra.Command{
		Use:   "update [schedule-id]",
		Short: "Update an existing scheduled scan",
		Args:  cobra.ExactArgs(1),
		Run:   runScheduleUpdate,
	}
	updateCmd.Flags().String("cron", "", "New cron expression")
	updateCmd.Flags().String("description", "", "New description")
	updateCmd.Flags().Bool("enabled", true, "Enable/disable the schedule")

	// Delete schedule
	deleteCmd := &cobra.Command{
		Use:   "delete [schedule-id]",
		Short: "Delete a scheduled scan",
		Args:  cobra.ExactArgs(1),
		Run:   runScheduleDelete,
	}

	// Trigger schedule
	triggerCmd := &cobra.Command{
		Use:   "trigger [schedule-id]",
		Short: "Manually trigger a scheduled scan",
		Args:  cobra.ExactArgs(1),
		Run:   runScheduleTrigger,
	}

	cmd.AddCommand(listCmd)
	cmd.AddCommand(createCmd)
	cmd.AddCommand(updateCmd)
	cmd.AddCommand(deleteCmd)
	cmd.AddCommand(triggerCmd)

	return cmd
}

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit and compliance operations",
		Long:  "View audit logs, generate compliance reports, and manage audit settings",
	}

	// View audit logs
	logsCmd := &cobra.Command{
		Use:   "logs",
		Short: "View audit logs",
		Run:   runAuditLogs,
	}
	logsCmd.Flags().String("start-time", "", "Start time for log query (RFC3339 format)")
	logsCmd.Flags().String("end-time", "", "End time for log query (RFC3339 format)")
	logsCmd.Flags().String("user", "", "Filter by user")
	logsCmd.Flags().String("action", "", "Filter by action")
	logsCmd.Flags().String("severity", "", "Filter by severity")
	logsCmd.Flags().Int("limit", 100, "Maximum number of entries to return")

	// Generate compliance report
	reportCmd := &cobra.Command{
		Use:   "report [standard]",
		Short: "Generate compliance report",
		Args:  cobra.ExactArgs(1),
		Run:   runAuditReport,
	}
	reportCmd.Flags().String("output", "json", "Output format (json, pdf, html)")
	reportCmd.Flags().String("output-file", "", "Output file path")
	reportCmd.Flags().String("period", "30d", "Reporting period")

	cmd.AddCommand(logsCmd)
	cmd.AddCommand(reportCmd)

	return cmd
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management",
		Long:  "Manage TypoSentinel Enterprise configuration",
	}

	// Validate config
	validateCmd := &cobra.Command{
		Use:   "validate [config-file]",
		Short: "Validate configuration file",
		Args:  cobra.MaximumNArgs(1),
		Run:   runConfigValidate,
	}

	// Generate sample config
	generateCmd := &cobra.Command{
		Use:   "generate [output-file]",
		Short: "Generate sample configuration file",
		Args:  cobra.ExactArgs(1),
		Run:   runConfigGenerate,
	}
	generateCmd.Flags().String("template", "enterprise", "Configuration template (basic, enterprise, minimal)")

	cmd.AddCommand(validateCmd)
	cmd.AddCommand(generateCmd)

	return cmd
}

func healthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "health",
		Short: "System health and diagnostics",
		Long:  "Check system health, view metrics, and run diagnostics",
	}

	// Health check
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Perform health check",
		Run:   runHealthCheck,
	}
	checkCmd.Flags().Bool("detailed", false, "Show detailed health information")

	// View metrics
	metricsCmd := &cobra.Command{
		Use:   "metrics",
		Short: "View system metrics",
		Run:   runHealthMetrics,
	}
	metricsCmd.Flags().String("format", "futuristic", "Output format (futuristic, table, json, prometheus)")

	cmd.AddCommand(checkCmd)
	cmd.AddCommand(metricsCmd)

	return cmd
}

func exportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export data and reports",
		Long:  "Export scan results, audit logs, and other data in various formats",
	}

	// Export scan results
	scansCmd := &cobra.Command{
		Use:   "scans [output-file]",
		Short: "Export scan results",
		Args:  cobra.ExactArgs(1),
		Run:   runExportScans,
	}
	scansCmd.Flags().String("format", "json", "Export format (json, csv, sarif, cyclonedx)")
	scansCmd.Flags().String("start-time", "", "Start time for export (RFC3339 format)")
	scansCmd.Flags().String("end-time", "", "End time for export (RFC3339 format)")
	scansCmd.Flags().StringSlice("repositories", nil, "Filter by repositories")

	// Export dashboard
	dashboardCmd := &cobra.Command{
		Use:   "dashboard [output-file]",
		Short: "Export dashboard data",
		Args:  cobra.ExactArgs(1),
		Run:   runExportDashboard,
	}
	dashboardCmd.Flags().String("format", "json", "Export format (json, pdf)")

	cmd.AddCommand(scansCmd)
	cmd.AddCommand(dashboardCmd)

	return cmd
}

func userCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "User management",
		Long:  "Manage users, roles, and permissions",
	}

	// List users
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all users",
		Run:   runUserList,
	}

	// Create user
	createCmd := &cobra.Command{
		Use:   "create [username]",
		Short: "Create a new user",
		Args:  cobra.ExactArgs(1),
		Run:   runUserCreate,
	}
	createCmd.Flags().String("email", "", "User email address")
	createCmd.Flags().String("role", "viewer", "User role (admin, operator, viewer)")
	createCmd.Flags().String("password", "", "User password (will prompt if not provided)")

	// Update user
	updateCmd := &cobra.Command{
		Use:   "update [username]",
		Short: "Update user information",
		Args:  cobra.ExactArgs(1),
		Run:   runUserUpdate,
	}
	updateCmd.Flags().String("email", "", "New email address")
	updateCmd.Flags().String("role", "", "New role")
	updateCmd.Flags().Bool("enabled", true, "Enable/disable user")

	// Delete user
	deleteCmd := &cobra.Command{
		Use:   "delete [username]",
		Short: "Delete a user",
		Args:  cobra.ExactArgs(1),
		Run:   runUserDelete,
	}

	cmd.AddCommand(listCmd)
	cmd.AddCommand(createCmd)
	cmd.AddCommand(updateCmd)
	cmd.AddCommand(deleteCmd)

	return cmd
}

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Security policy management",
		Long:  "Manage security policies, rules, and enforcement settings",
	}

	// List policies
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all security policies",
		Run:   runPolicyList,
	}

	// Create policy
	createCmd := &cobra.Command{
		Use:   "create [policy-file]",
		Short: "Create a new security policy from file",
		Args:  cobra.ExactArgs(1),
		Run:   runPolicyCreate,
	}

	// Validate policy
	validateCmd := &cobra.Command{
		Use:   "validate [policy-file]",
		Short: "Validate a security policy file",
		Args:  cobra.ExactArgs(1),
		Run:   runPolicyValidate,
	}

	cmd.AddCommand(listCmd)
	cmd.AddCommand(createCmd)
	cmd.AddCommand(validateCmd)

	return cmd
}

func integrationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "integration",
		Short: "Integration management",
		Long:  "Manage integrations with external systems (SIEM, Slack, etc.)",
	}

	// List integrations
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all configured integrations",
		Run:   runIntegrationList,
	}

	// Test integration
	testCmd := &cobra.Command{
		Use:   "test [integration-name]",
		Short: "Test an integration connection",
		Args:  cobra.ExactArgs(1),
		Run:   runIntegrationTest,
	}

	cmd.AddCommand(listCmd)
	cmd.AddCommand(testCmd)

	return cmd
}

// Command implementations

func runServer(cmd *cobra.Command, args []string) {
	// Record application start time for uptime calculation
	startTime = time.Now()
	
	bind, _ := cmd.Flags().GetString("bind")
	enableUI, _ := cmd.Flags().GetBool("enable-ui")
	enableAPI, _ := cmd.Flags().GetBool("enable-api")
	enableScheduler, _ := cmd.Flags().GetBool("enable-scheduler")
	enableMonitoring, _ := cmd.Flags().GetBool("enable-monitoring")
	enableAudit, _ := cmd.Flags().GetBool("enable-audit")

	fmt.Printf("Starting TypoSentinel Enterprise Server...\n")
	fmt.Printf("Binding to: %s\n", bind)
	fmt.Printf("Web UI: %v\n", enableUI)
	fmt.Printf("REST API: %v\n", enableAPI)
	fmt.Printf("Scheduler: %v\n", enableScheduler)
	fmt.Printf("Monitoring: %v\n", enableMonitoring)
	fmt.Printf("Audit Logging: %v\n", enableAudit)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize logger
	loggerConfig := &config.LoggingConfig{
		Level:  logLevel,
		Format: "json",
		Output: "stdout",
	}
	logger, err := logging.NewLogger(loggerConfig)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Load configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Load enterprise configuration
	enterpriseConfig := config.DefaultEnterpriseConfig()

	// Create logger adapters
	authLoggerAdapter := &AuthLoggerAdapter{logger: logger}

	// Initialize pkg logger
	pkgLogger := pkglogger.New()

	// Initialize services
	var auditLogger *audit.AuditLogger
	if enableAudit {
		// Convert config.AuditConfig to audit.AuditConfig
		auditConfig := &audit.AuditConfig{
			Enabled:       enterpriseConfig.Audit.Enabled,
			BufferSize:    1000,
			FlushInterval: 30 * time.Second,
			Destinations: []audit.AuditDestination{
				{
					Type:    enterpriseConfig.Audit.Destination,
					Enabled: true,
					Settings: map[string]interface{}{
						"path": "/var/log/typosentinel/audit.log",
					},
				},
			},
		}
		auditLogger, err = audit.NewAuditLogger(auditConfig, pkgLogger)
		if err != nil {
			log.Fatalf("Failed to initialize audit logger: %v", err)
		}
		auditLogger.Start(ctx)
		defer auditLogger.Stop()
	}

	var monitoringService *monitoring.MonitoringService
	if enableMonitoring {
		monitoringService = monitoring.NewMonitoringService(enterpriseConfig.Monitoring, pkgLogger)
		monitoringService.Start(ctx)
		defer monitoringService.Stop()
	}

	// Initialize repository manager
	repoManagerConfig := &repository.ManagerConfig{
		MaxConcurrentScans: 10,
		ScanTimeout:        30 * time.Minute,
		RetryAttempts:      3,
		RetryDelay:         5 * time.Second,
		EnableMetrics:      true,
	}
	repoManager := repository.NewManager(repoManagerConfig)

	// Initialize scheduler
	var scheduler *orchestrator.ScanScheduler
	if enableScheduler {
		// TODO: Initialize queue and scheduler
		fmt.Println("Scheduler initialization would go here")
	}

	// Initialize database service
	dbConfig := &database.DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "typosentinel",
		Password: "password",
		DBName:   "typosentinel",
		SSLMode:  "disable",
		MaxConns: 10,
		MaxIdle:  5,
	}
	dbService, err := database.NewDatabaseService(dbConfig)
	if err != nil {
		log.Printf("Warning: Failed to initialize database service: %v", err)
		// Continue without database service for now
		dbService = nil
	}
	if dbService != nil {
		defer dbService.Close()
	}

	// Initialize policy manager
	policyEngine := auth.NewPolicyEngine(authLoggerAdapter)
	rbacEngine := auth.NewRBACEngine(&config.AuthzConfig{})
	policyManager := auth.NewEnterprisePolicyManager(policyEngine, rbacEngine, authLoggerAdapter)

	// Initialize dashboard with start time
	dashboardConfig := &dashboard.DashboardConfig{
		Enabled:         true,
		RefreshInterval: 30 * time.Second,
		RetentionPeriod: 24 * time.Hour,
		MaxDataPoints:   100,
		RealTimeUpdates: true,
		StartTime:       startTime,
	}
	dashboardInstance := dashboard.NewEnterpriseDashboard(
		pkgLogger,
		monitoringService,
		scheduler,
		repoManager,
		policyManager,
		dbService,
		dashboardConfig,
	)

	// Initialize integration hub
	eventBus := events.NewEventBus(pkgLogger, 1000)
	integrationHub := hub.NewIntegrationHub(eventBus, cfg.Integrations, pkgLogger)
	integrationHub.Initialize(ctx)
	defer integrationHub.Stop(ctx)

	// Setup HTTP server
	if enableAPI || enableUI {
		router := gin.Default()

		// Add middleware
		router.Use(gin.Logger())
		router.Use(gin.Recovery())

		// Register API routes
			if enableAPI {
				enterpriseHandler := rest.NewEnterpriseHandler(repoManager, scheduler)
				enterpriseHandler.RegisterRoutes(router)
				dashboardInstance.RegisterRoutes(router)
			}

		// Serve static files for UI
		if enableUI {
			router.Static("/static", "./web/static")
			router.LoadHTMLGlob("./web/templates/*")
			router.GET("/", func(c *gin.Context) {
				c.HTML(200, "dashboard.html", gin.H{
					"title": "TypoSentinel Enterprise Dashboard",
				})
			})
		}

		// Start server
		go func() {
			if err := router.Run(bind); err != nil {
				log.Printf("Server failed to start: %v", err)
				cancel()
			}
		}()
	}

	fmt.Printf("TypoSentinel Enterprise Server started successfully\n")
	fmt.Printf("Access the dashboard at: http://%s\n", bind)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		fmt.Println("\nShutting down gracefully...")
	case <-ctx.Done():
		fmt.Println("\nContext cancelled, shutting down...")
	}

	cancel()
	time.Sleep(2 * time.Second) // Give services time to shut down
	fmt.Println("Server stopped")
}

// Repository scanning implementation
func runScanRepository(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: scan repository <platform> <owner/repo>")
		os.Exit(1)
	}
	
	platform := args[0]
	repo := args[1]
	fmt.Printf("Scanning repository: %s on %s\n", repo, platform)
	
	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	cfg := cfgManager.Get()
	
	// Parse repository identifier
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		log.Fatalf("Invalid repository format. Expected: owner/repo")
	}
	
	owner := parts[0]
	repoName := parts[1]
	
	fmt.Printf("Repository: %s\n", repo)
	fmt.Printf("Platform: %s\n", platform)
	fmt.Printf("Owner: %s\n", owner)
	fmt.Printf("Name: %s\n", repoName)
	fmt.Printf("Configuration loaded: %s environment\n", cfg.App.Environment)
	
	// Get command flags
	branch, _ := cmd.Flags().GetString("branch")
	outputFormat, _ := cmd.Flags().GetString("output")
	_, _ = cmd.Flags().GetString("output-file") // outputFile for future use
	includeDev, _ := cmd.Flags().GetBool("include-dev")
	
	ctx := context.Background()
	
	// Initialize repository manager
	repoManager := repository.NewManager(repository.DefaultManagerConfig())
	
	// Initialize connector based on platform
	var connector repository.Connector
	var err error
	
	switch platform {
	case "github":
		connector, err = initializeGitHubConnector(cfg)
	case "gitlab":
		connector, err = initializeGitLabConnector(cfg)
	case "bitbucket":
		connector, err = initializeBitbucketConnector(cfg)
	case "azuredevops":
		connector, err = initializeAzureDevOpsConnector(cfg)
	default:
		log.Fatalf("Platform %s not supported. Supported platforms: github, gitlab, bitbucket, azuredevops", platform)
	}
	
	if err != nil {
		log.Fatalf("Failed to initialize %s connector: %v", platform, err)
	}
	
	// Register connector with manager
	if err := repoManager.RegisterConnector(platform, connector); err != nil {
		log.Fatalf("Failed to register %s connector: %v", platform, err)
	}
	
	// Get connector
	connector, err = repoManager.GetConnector(platform)
	if err != nil {
		log.Fatalf("Failed to get connector for platform %s: %v", platform, err)
	}
	
	// Get repository information
	repoInfo, err := connector.GetRepository(ctx, owner, repoName)
	if err != nil {
		log.Fatalf("Failed to get repository information: %v", err)
	}
	
	fmt.Printf("Found repository: %s\n", repoInfo.FullName)
	fmt.Printf("Language: %s\n", repoInfo.Language)
	fmt.Printf("Stars: %d\n", repoInfo.StarCount)
	
	// Create scan request
	scanRequest := &repository.ScanRequest{
		Repository:  repoInfo,
		Branch:      branch,
		ScanID:      fmt.Sprintf("cli_scan_%d", time.Now().Unix()),
		RequestedBy: "cli",
		Priority:    1,
		Options: repository.ScanOptions{
			IncludeDev:    includeDev,
			OutputFormats: []string{outputFormat},
		},
		CreatedAt: time.Now(),
	}
	
	fmt.Println("Starting repository scan...")
	
	// Perform scan
	result, err := repoManager.ScanRepository(ctx, scanRequest)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}
	
	// Output results
	if err := outputScanResult(result); err != nil {
		log.Fatalf("Failed to output results: %v", err)
	}
	
	fmt.Println("Scan completed successfully!")
}

func runScanOrganization(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: scan organization <platform> <org>")
		os.Exit(1)
	}
	
	platform := args[0]
	org := args[1]
	fmt.Printf("Scanning organization: %s on %s\n", org, platform)
	
	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	cfg := cfgManager.Get()
	
	fmt.Printf("Organization: %s\n", org)
	fmt.Printf("Platform: %s\n", platform)
	fmt.Printf("Configuration loaded: %s environment\n", cfg.App.Environment)
	
	// Get command flags
	maxRepos, _ := cmd.Flags().GetInt("max-repos")
	includePrivate, _ := cmd.Flags().GetBool("include-private")
	includeForks, _ := cmd.Flags().GetBool("include-forks")
	includeArchived, _ := cmd.Flags().GetBool("include-archived")
	languages, _ := cmd.Flags().GetStringSlice("languages")
	outputFormat, _ := cmd.Flags().GetString("output")
	reportFile, _ := cmd.Flags().GetString("report-file")
	
	ctx := context.Background()
	
	// Initialize repository manager
	repoManager := repository.NewManager(repository.DefaultManagerConfig())
	
	// Initialize connector based on platform
	var connector repository.Connector
	var err error
	
	switch platform {
	case "github":
		connector, err = initializeGitHubConnector(cfg)
	case "gitlab":
		connector, err = initializeGitLabConnector(cfg)
	case "bitbucket":
		connector, err = initializeBitbucketConnector(cfg)
	case "azuredevops":
		connector, err = initializeAzureDevOpsConnector(cfg)
	default:
		log.Fatalf("Platform %s not supported. Supported platforms: github, gitlab, bitbucket, azuredevops", platform)
	}
	
	if err != nil {
		log.Fatalf("Failed to initialize %s connector: %v", platform, err)
	}
	
	// Register connector with manager
	if err := repoManager.RegisterConnector(platform, connector); err != nil {
		log.Fatalf("Failed to register %s connector: %v", platform, err)
	}
	
	// Get connector
	connector, err = repoManager.GetConnector(platform)
	if err != nil {
		log.Fatalf("Failed to get connector for platform %s: %v", platform, err)
	}
	
	// Get organization
	orgInfo, err := connector.GetOrganization(ctx, org)
	if err != nil {
		log.Fatalf("Failed to get organization: %v", err)
	}
	
	fmt.Printf("Found organization: %s\n", orgInfo.Login)
	
	// List repositories with filters
	repos, err := connector.ListOrgRepositories(ctx, org, &repository.RepositoryFilter{
		IncludePrivate:  includePrivate,
		IncludeArchived: includeArchived,
		IncludeForks:    includeForks,
		Languages:       languages,
	})
	if err != nil {
		log.Fatalf("Failed to list repositories: %v", err)
	}
	
	// Limit results if maxRepos is specified
	if maxRepos > 0 && len(repos) > maxRepos {
		repos = repos[:maxRepos]
	}
	
	fmt.Printf("Found %d repositories\n", len(repos))
	
	// Track scan results for reporting
	var allResults []*repository.ScanResult
	successCount := 0
	errorCount := 0
	
	// Scan each repository
	for i, repo := range repos {
		fmt.Printf("\nScanning repository %d/%d: %s\n", i+1, len(repos), repo.FullName)
		
		// Create scan request
		scanRequest := &repository.ScanRequest{
			Repository:  repo,
			ScanID:      fmt.Sprintf("org_scan_%s_%d_%d", org, time.Now().Unix(), i),
			RequestedBy: "cli",
			Priority:    1,
			Options: repository.ScanOptions{
				IncludeDev:    true,
				OutputFormats: []string{outputFormat},
			},
			CreatedAt: time.Now(),
		}

		// Perform scan
		result, err := repoManager.ScanRepository(ctx, scanRequest)
		if err != nil {
			fmt.Printf("  Error scanning %s: %v\n", repo.FullName, err)
			errorCount++
			continue
		}

		// Output brief results
		if result != nil {
			fmt.Printf("  Status: %s\n", result.Status)
			fmt.Printf("  Duration: %v\n", result.Duration)
			fmt.Printf("  Dependency Files: %d\n", len(result.DependencyFiles))
			allResults = append(allResults, result)
			successCount++
		} else {
			fmt.Printf("  No scan results returned\n")
			errorCount++
		}
	}
	
	// Generate consolidated report if requested
	if reportFile != "" {
		fmt.Printf("\nGenerating consolidated report: %s\n", reportFile)
		// TODO: Implement report generation
	}
	
	fmt.Printf("\nOrganization scan completed!\n")
	fmt.Printf("Successful scans: %d\n", successCount)
	fmt.Printf("Failed scans: %d\n", errorCount)
	fmt.Printf("Total repositories: %d\n", len(repos))
}

func runScanConfig(cmd *cobra.Command, args []string) {
	fmt.Printf("Scanning from config: %s\n", args[0])
	// TODO: Implement config-based scanning
}

func runScheduleList(cmd *cobra.Command, args []string) {
	fmt.Println("Listing scheduled scans...")
	// TODO: Implement schedule listing
}

func runScheduleCreate(cmd *cobra.Command, args []string) {
	fmt.Printf("Creating schedule: %s\n", args[0])
	// TODO: Implement schedule creation
}

func runScheduleUpdate(cmd *cobra.Command, args []string) {
	fmt.Printf("Updating schedule: %s\n", args[0])
	// TODO: Implement schedule update
}

func runScheduleDelete(cmd *cobra.Command, args []string) {
	fmt.Printf("Deleting schedule: %s\n", args[0])
	// TODO: Implement schedule deletion
}

func runScheduleTrigger(cmd *cobra.Command, args []string) {
	fmt.Printf("Triggering schedule: %s\n", args[0])
	// TODO: Implement schedule triggering
}

func runAuditLogs(cmd *cobra.Command, args []string) {
	fmt.Println("Viewing audit logs...")
	// TODO: Implement audit log viewing
}

func runAuditReport(cmd *cobra.Command, args []string) {
	fmt.Printf("Generating compliance report for: %s\n", args[0])
	// TODO: Implement compliance reporting
}

func runConfigValidate(cmd *cobra.Command, args []string) {
	configFile := configFile
	if len(args) > 0 {
		configFile = args[0]
	}
	fmt.Printf("Validating configuration: %s\n", configFile)
	// TODO: Implement config validation
}

func runConfigGenerate(cmd *cobra.Command, args []string) {
	fmt.Printf("Generating configuration: %s\n", args[0])
	// TODO: Implement config generation
}

func runHealthCheck(cmd *cobra.Command, args []string) {
	fmt.Println("Performing health check...")
	// TODO: Implement health check
}

func runHealthMetrics(cmd *cobra.Command, args []string) {
	fmt.Println("Viewing system metrics...")
	// TODO: Implement metrics viewing
}

func runExportScans(cmd *cobra.Command, args []string) {
	fmt.Printf("Exporting scan results to: %s\n", args[0])
	// TODO: Implement scan export
}

func runExportDashboard(cmd *cobra.Command, args []string) {
	fmt.Printf("Exporting dashboard to: %s\n", args[0])
	// TODO: Implement dashboard export
}

func runUserList(cmd *cobra.Command, args []string) {
	fmt.Println("Listing users...")
	// TODO: Implement user listing
}

func runUserCreate(cmd *cobra.Command, args []string) {
	fmt.Printf("Creating user: %s\n", args[0])
	// TODO: Implement user creation
}

func runUserUpdate(cmd *cobra.Command, args []string) {
	fmt.Printf("Updating user: %s\n", args[0])
	// TODO: Implement user update
}

func runUserDelete(cmd *cobra.Command, args []string) {
	fmt.Printf("Deleting user: %s\n", args[0])
	// TODO: Implement user deletion
}

func runPolicyList(cmd *cobra.Command, args []string) {
	fmt.Println("Listing security policies...")
	// TODO: Implement policy listing
}

func runPolicyCreate(cmd *cobra.Command, args []string) {
	fmt.Printf("Creating policy from: %s\n", args[0])
	// TODO: Implement policy creation
}

func runPolicyValidate(cmd *cobra.Command, args []string) {
	fmt.Printf("Validating policy: %s\n", args[0])
	// TODO: Implement policy validation
}

func runIntegrationList(cmd *cobra.Command, args []string) {
	fmt.Println("Listing integrations...")
	// TODO: Implement integration listing
}

func runIntegrationTest(cmd *cobra.Command, args []string) {
	fmt.Printf("Testing integration: %s\n", args[0])
	// TODO: Implement integration testing
}

// initConfig reads in config file and ENV variables if set
func initConfig() {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.AddConfigPath("$HOME")
		viper.AddConfigPath(".")
		viper.SetConfigName(".typosentinel-enterprise")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
		}
	}
}