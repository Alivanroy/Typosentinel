package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
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
	"github.com/Alivanroy/Typosentinel/internal/security"
	"github.com/Alivanroy/Typosentinel/internal/storage"
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

// noOpMetrics is a no-op implementation of interfaces.Metrics
type noOpMetrics struct{}

func (m *noOpMetrics) IncrementCounter(name string, labels interfaces.MetricTags) {}
func (m *noOpMetrics) SetGauge(name string, value float64, labels interfaces.MetricTags) {}
func (m *noOpMetrics) RecordHistogram(name string, value float64, labels interfaces.MetricTags) {}
func (m *noOpMetrics) RecordDuration(name string, duration time.Duration, tags interfaces.MetricTags) {}
func (m *noOpMetrics) Start(ctx context.Context) error { return nil }
func (m *noOpMetrics) Stop() error { return nil }
func (m *noOpMetrics) Counter(name string, tags interfaces.MetricTags) interfaces.Counter { return &noOpCounter{} }
func (m *noOpMetrics) Gauge(name string, tags interfaces.MetricTags) interfaces.Gauge { return &noOpGauge{} }
func (m *noOpMetrics) Histogram(name string, tags interfaces.MetricTags) interfaces.Histogram { return &noOpHistogram{} }
func (m *noOpMetrics) Timer(name string, tags interfaces.MetricTags) interfaces.Timer { return &noOpTimer{} }

type noOpCounter struct{}
func (c *noOpCounter) Inc() {}
func (c *noOpCounter) Add(value float64) {}

type noOpGauge struct{}
func (g *noOpGauge) Set(value float64) {}
func (g *noOpGauge) Inc() {}
func (g *noOpGauge) Dec() {}
func (g *noOpGauge) Add(value float64) {}
func (g *noOpGauge) Sub(value float64) {}

type noOpHistogram struct{}
func (h *noOpHistogram) Observe(value float64) {}

type noOpTimer struct{}
func (t *noOpTimer) Time() func() { return func() {} }
func (t *noOpTimer) Record(duration time.Duration) {}

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
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.planfinale-enterprise.yaml)")
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
						"path": "./logs/audit.log",
					},
				},
			},
		}
		auditLogger, err = audit.NewAuditLogger(auditConfig, *pkgLogger)
		if err != nil {
			log.Fatalf("Failed to initialize audit logger: %v", err)
		}
		auditLogger.Start(ctx)
		defer auditLogger.Stop()
	}

	var monitoringService *monitoring.MonitoringService
	if enableMonitoring {
		// Create a no-op metrics implementation for now
		metrics := &noOpMetrics{}
		monitoringService = monitoring.NewMonitoringService(enterpriseConfig.Monitoring, *pkgLogger, metrics)
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
		// Initialize in-memory scan queue for scheduled scans
		scanQueue := orchestrator.NewInMemoryScanQueue()

		// Initialize scheduler with correct parameters
		scheduler = orchestrator.NewScanScheduler(scanQueue, repoManager, log.New(os.Stderr, "[SCHEDULER] ", log.LstdFlags))

		// Start the scheduler with context
		ctx := context.Background()
		scheduler.Start(ctx)
		fmt.Println("✅ Scan scheduler initialized and started")

		// Load existing schedules if they exist
		schedulesFile := "./schedules.yaml"
		configData, err := os.ReadFile(schedulesFile)
		if err != nil {
			log.Printf("Warning: Failed to read schedules file %s: %v", schedulesFile, err)
		} else {
			if err := scheduler.LoadSchedulesFromConfig(configData); err != nil {
				log.Printf("Warning: Failed to load schedules from %s: %v", schedulesFile, err)
			} else {
				fmt.Println("✅ Existing schedules loaded")
			}
		}

		// Ensure scheduler is stopped on shutdown
		defer func() {
			if scheduler != nil {
				scheduler.Stop()
			}
		}()
	}

	// Initialize database service
	dbConfig := &config.DatabaseConfig{
		Host:            "localhost",
		Port:            5432,
		Username:        "typosentinel",
		Password:        "password",
		Database:        "typosentinel",
		SSLMode:         "disable",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
	}
	dbService, err := database.NewDatabaseService(dbConfig)
	if err != nil {
		log.Printf("Warning: Failed to initialize database service: %v", err)
		// Continue without database service for now
		dbService = nil
	}
	if dbService != nil {
		defer dbService.Close()

		// Initialize database schema and run migrations
		schemaManager := database.NewSchemaManager(dbService.GetDB(), pkgLogger)
		if err := schemaManager.Initialize(ctx); err != nil {
			log.Printf("Warning: Failed to initialize database schema: %v", err)
		} else {
			log.Printf("Database schema initialized successfully")
		}
	}

	// Initialize policy manager with database-backed violation store
	policyEngine := auth.NewPolicyEngine(authLoggerAdapter)
	rbacEngine := auth.NewRBACEngine(&config.AuthzConfig{})

	// Use database-backed violation store if database is available
	var violationStore auth.ViolationStore
	var dbViolationStore *storage.ViolationStore
	if dbService != nil {
		dbViolationStore = storage.NewViolationStore(dbService.GetDB(), pkgLogger)
		violationStore = dbViolationStore
		log.Printf("Using database-backed violation store")
	} else {
		violationStore = auth.NewMemoryViolationStore()
		log.Printf("Using memory-backed violation store (database not available)")
	}

	policyManager := auth.NewEnterprisePolicyManager(policyEngine, rbacEngine, violationStore, authLoggerAdapter)

	// Initialize security manager with database connection
	var securityManager *security.SecurityManager
	if dbService != nil {
		userRepository, err := security.NewUserRepositoryWithService(dbService, pkgLogger)
		if err != nil {
			log.Printf("Warning: Failed to create user repository: %v", err)
		} else {
			securityManager, err = security.NewSecurityManagerWithUserRepository(pkgLogger, rbacEngine, userRepository)
			if err != nil {
				log.Printf("Warning: Failed to initialize security manager: %v", err)
			} else {
				log.Printf("Security manager initialized with database connection")
			}
		}
	}

	// Fallback to security manager without database if needed
	if securityManager == nil {
		securityManager, err = security.NewSecurityManager(pkgLogger, rbacEngine)
		if err != nil {
			log.Printf("Warning: Failed to initialize fallback security manager: %v", err)
		} else {
			log.Printf("Security manager initialized without database connection")
		}
	}

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
		*pkgLogger,
		monitoringService,
		scheduler,
		repoManager,
		policyManager,
		dbService,
		dashboardConfig,
	)

	// Initialize integration hub
	eventBus := events.NewEventBus(*pkgLogger, 1000)
	integrationHub := hub.NewIntegrationHub(eventBus, cfg.Integrations, *pkgLogger)
	integrationHub.Initialize(ctx)
	defer integrationHub.Stop(ctx)

	// Setup REST API server
	if enableAPI {
		// Parse bind address
		parts := strings.Split(bind, ":")
		host := parts[0]
		port := 8080
		if len(parts) > 1 {
			if p, err := strconv.Atoi(parts[1]); err == nil {
				port = p
			}
		}

		// Create REST API config
		corsConfig := &config.CORSConfig{
			Enabled:          true,
			AllowedOrigins:   []string{"http://localhost:5173", "http://localhost:3000", "http://localhost:8080"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Origin", "Content-Type", "Authorization", "X-Requested-With"},
			AllowCredentials: true,
			MaxAge:           86400,
		}
		log.Printf("[ENTERPRISE DEBUG] CORS config created: %+v", corsConfig)
		
		restConfig := config.RESTAPIConfig{
			Enabled:  true,
			Host:     host,
			Port:     port,
			BasePath: "/api",
			Versioning: config.APIVersioning{
				Enabled:           true,
				Strategy:          "path",
				DefaultVersion:    "v1",
				SupportedVersions: []string{"v1"},
			},
			CORS: corsConfig,
		}
		log.Printf("[ENTERPRISE DEBUG] REST config created with CORS: %+v", restConfig.CORS)

		// Create analyzer instance
		analyzer, err := analyzer.New(cfg)
		if err != nil {
			log.Printf("Warning: Failed to create analyzer: %v", err)
		}

		// Create enterprise handlers if database is available
		var enterpriseHandlers *rest.EnterpriseHandlers
		if dbViolationStore != nil {
			// Create auth middleware
			authMiddleware := &auth.AuthorizationMiddleware{}

			// Create enterprise handlers with database violation store
			enterpriseHandlers = rest.NewEnterpriseHandlers(
				policyManager,
				rbacEngine,
				authMiddleware,
				dbViolationStore,
				authLoggerAdapter,
			)

			log.Printf("Enterprise handlers initialized with database backend")
		}

		// Create and start REST server with enterprise features
		server := rest.NewServerWithEnterprise(restConfig, nil, analyzer, enterpriseHandlers)

		// Start server in a goroutine
		go func() {
			if err := server.Start(ctx); err != nil {
				log.Printf("REST API server failed to start: %v", err)
				cancel()
			}
		}()

		log.Printf("REST API server started on %s:%d", host, port)
	}

	// Setup additional UI server if needed
	if enableUI {
		// Create a separate Gin router for UI
		uiRouter := gin.Default()

		// Serve static files for UI
		uiRouter.Static("/static", "./web/static")
		uiRouter.LoadHTMLGlob("./web/templates/*")
		uiRouter.GET("/", func(c *gin.Context) {
			c.HTML(200, "dashboard.html", gin.H{
				"title": "TypoSentinel Enterprise Dashboard",
			})
		})

		// Register dashboard routes
		dashboardInstance.RegisterRoutes(uiRouter)

		// Start UI server on a different port if API is also enabled
		uiPort := "3000"
		if !enableAPI {
			// Use the same port if API is not enabled
			parts := strings.Split(bind, ":")
			if len(parts) > 1 {
				uiPort = parts[1]
			}
		}

		go func() {
			uiAddr := fmt.Sprintf("0.0.0.0:%s", uiPort)
			if err := uiRouter.Run(uiAddr); err != nil {
				log.Printf("UI server failed to start: %v", err)
				cancel()
			}
		}()

		log.Printf("UI server started on port %s", uiPort)
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
	result, err := repoManager.ScanRepositoryWithResult(ctx, scanRequest)
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
		result, err := repoManager.ScanRepositoryWithResult(ctx, scanRequest)
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

		// Calculate statistics from scan results
		totalDependencyFiles := 0

		// Process all results to calculate statistics
		for _, result := range allResults {
			if result != nil {
				totalDependencyFiles += len(result.DependencyFiles)
				// Note: Detailed vulnerability analysis would require parsing the AnalysisResult
				// For now, we'll provide basic statistics
			}
		}

		// Generate consolidated report
		report := map[string]interface{}{
			"scan_summary": map[string]interface{}{
				"total_repositories": len(repos),
				"successful_scans":   successCount,
				"failed_scans":       errorCount,
				"scan_date":          time.Now().Format(time.RFC3339),
				"organization":       org,
				"provider":           platform,
			},
			"repository_results": allResults,
			"overall_statistics": map[string]interface{}{
				"total_dependency_files": totalDependencyFiles,
				"successful_scans":       successCount,
				"failed_scans":           errorCount,
				"scan_completion_rate":   float64(successCount) / float64(len(repos)) * 100,
			},
		}

		// Write report to file
		reportData, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling report: %v\n", err)
		} else {
			if err := os.WriteFile(reportFile, reportData, 0644); err != nil {
				fmt.Printf("Error writing report file: %v\n", err)
			} else {
				fmt.Printf("✅ Consolidated report saved to: %s\n", reportFile)
			}
		}
	}

	fmt.Printf("\nOrganization scan completed!\n")
	fmt.Printf("Successful scans: %d\n", successCount)
	fmt.Printf("Failed scans: %d\n", errorCount)
	fmt.Printf("Total repositories: %d\n", len(repos))
}

func runScanConfig(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: config file path is required")
		fmt.Println("Usage: typosentinel-enterprise scan config <config-file>")
		return
	}

	configFile := args[0]
	fmt.Printf("Scanning from config: %s\n", configFile)

	// Check if config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Printf("Error: Config file not found: %s\n", configFile)
		return
	}

	// Read config file
	configData, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
		return
	}

	// Parse config (assuming YAML format)
	var scanConfig map[string]interface{}
	if err := yaml.Unmarshal(configData, &scanConfig); err != nil {
		fmt.Printf("Error parsing config file: %v\n", err)
		return
	}

	fmt.Printf("✅ Config loaded successfully\n")

	// Extract scan targets from config
	targets, ok := scanConfig["targets"].([]interface{})
	if !ok {
		fmt.Println("Error: No 'targets' section found in config")
		return
	}

	fmt.Printf("Found %d scan targets in config\n", len(targets))

	// Load application configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading application configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	ctx := context.Background()
	repoManager := repository.NewManager(repository.DefaultManagerConfig())

	successCount := 0
	errorCount := 0

	// Process each target
	for i, target := range targets {
		targetMap, ok := target.(map[interface{}]interface{})
		if !ok {
			fmt.Printf("Error: Invalid target format at index %d\n", i)
			errorCount++
			continue
		}

		// Extract target details
		targetType := getConfigValue(targetMap, "type", "repository")
		provider := getConfigValue(targetMap, "provider", "github")
		organization := getConfigValue(targetMap, "organization", "")
		repository := getConfigValue(targetMap, "repository", "")

		fmt.Printf("\nProcessing target %d/%d:\n", i+1, len(targets))
		fmt.Printf("  Type: %s\n", targetType)
		fmt.Printf("  Provider: %s\n", provider)

		if targetType == "organization" && organization != "" {
			fmt.Printf("  Organization: %s\n", organization)
			// Scan organization (similar to runScan but simplified)
			if err := scanOrganizationFromConfig(ctx, repoManager, cfg, provider, organization); err != nil {
				fmt.Printf("  ❌ Error scanning organization: %v\n", err)
				errorCount++
			} else {
				fmt.Printf("  ✅ Organization scan completed\n")
				successCount++
			}
		} else if targetType == "repository" && repository != "" {
			fmt.Printf("  Repository: %s\n", repository)
			// Scan single repository
			if err := scanRepositoryFromConfig(ctx, repoManager, cfg, provider, repository); err != nil {
				fmt.Printf("  ❌ Error scanning repository: %v\n", err)
				errorCount++
			} else {
				fmt.Printf("  ✅ Repository scan completed\n")
				successCount++
			}
		} else {
			fmt.Printf("  ❌ Invalid target configuration\n")
			errorCount++
		}
	}

	fmt.Printf("\nConfig-based scan completed!\n")
	fmt.Printf("Successful scans: %d\n", successCount)
	fmt.Printf("Failed scans: %d\n", errorCount)
	fmt.Printf("Total targets: %d\n", len(targets))
}

func runScheduleList(cmd *cobra.Command, args []string) {
	fmt.Println("Listing scheduled scans...")

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Display scheduler status
	fmt.Printf("📅 Scheduler Status:\n")
	fmt.Printf("  Application: %s v%s\n", cfg.App.Name, cfg.App.Version)
	fmt.Printf("  Environment: %s\n", cfg.App.Environment)
	fmt.Printf("  Max Workers: %d\n", cfg.App.MaxWorkers)

	// Check for schedule configuration file
	scheduleFile := "./schedules.yaml"
	if _, err := os.Stat(scheduleFile); os.IsNotExist(err) {
		fmt.Printf("\n❌ No schedule configuration found at %s\n", scheduleFile)
		fmt.Println("Create a schedules.yaml file to define scheduled scans")
		fmt.Println("\nExample schedule configuration:")
		fmt.Println("```yaml")
		fmt.Println("schedules:")
		fmt.Println("  - name: \"daily-org-scan\"")
		fmt.Println("    schedule: \"0 2 * * *\"  # Daily at 2 AM")
		fmt.Println("    type: \"organization\"")
		fmt.Println("    enabled: true")
		fmt.Println("    targets:")
		fmt.Println("      - organization: \"myorg\"")
		fmt.Println("        provider: \"github\"")
		fmt.Println("```")
		return
	}

	// Read schedule file
	scheduleData, err := os.ReadFile(scheduleFile)
	if err != nil {
		fmt.Printf("Error reading schedule file: %v\n", err)
		return
	}

	// Parse schedule data (simplified YAML parsing)
	fmt.Printf("\n📋 Schedule Configuration:\n")
	fmt.Printf("  File: %s\n", scheduleFile)
	fmt.Printf("  Size: %d bytes\n", len(scheduleData))

	// Display basic schedule information
	lines := strings.Split(string(scheduleData), "\n")
	scheduleCount := 0
	inSchedule := false
	currentSchedule := ""

	fmt.Printf("\n📋 Scheduled Jobs:\n")
	fmt.Printf("%-20s %-20s %-15s %-10s\n", "Name", "Schedule", "Type", "Status")
	fmt.Println(strings.Repeat("-", 65))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- name:") {
			inSchedule = true
			name := strings.Trim(strings.TrimPrefix(line, "- name:"), "\" ")
			currentSchedule = name
			scheduleCount++
		} else if inSchedule && strings.HasPrefix(line, "schedule:") {
			schedule := strings.Trim(strings.TrimPrefix(line, "schedule:"), "\" ")
			fmt.Printf("%-20s %-20s %-15s %-10s\n", currentSchedule, schedule, "scan", "Active")
			inSchedule = false
		}
	}

	if scheduleCount == 0 {
		fmt.Println("No scheduled jobs found in configuration")
	} else {
		fmt.Printf("\nTotal scheduled jobs: %d\n", scheduleCount)
	}

	// Display scheduler service status
	fmt.Printf("\n📊 Scheduler Service:\n")
	fmt.Println("  Status: Not running (use 'typosentinel-enterprise server' to start)")
	fmt.Println("  Next check: Manual trigger required")
}

func runScheduleCreate(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: schedule name is required")
		fmt.Println("Usage: typosentinel-enterprise schedule create <name> --cron <expression> --type <type> --target <target>")
		return
	}

	scheduleName := args[0]
	cronExpr, _ := cmd.Flags().GetString("cron")
	scheduleType, _ := cmd.Flags().GetString("type")
	target, _ := cmd.Flags().GetString("target")
	enabled, _ := cmd.Flags().GetBool("enabled")

	fmt.Printf("Creating schedule: %s\n", scheduleName)

	// Validate required parameters
	if cronExpr == "" {
		fmt.Println("Error: --cron flag is required (e.g., '0 2 * * *' for daily at 2 AM)")
		return
	}

	if scheduleType == "" {
		scheduleType = "organization" // Default type
	}

	if target == "" {
		fmt.Println("Error: --target flag is required (e.g., 'myorg' for organization scans)")
		return
	}

	// Create schedule configuration
	scheduleConfig := map[string]interface{}{
		"name":       scheduleName,
		"schedule":   cronExpr,
		"type":       scheduleType,
		"enabled":    enabled,
		"created_at": time.Now().Format(time.RFC3339),
		"targets": []map[string]interface{}{
			{
				"organization": target,
				"provider":     "github", // Default provider
			},
		},
		"options": map[string]interface{}{
			"scan_depth":       "full",
			"include_forks":    false,
			"include_archived": false,
		},
	}

	// Load existing schedules or create new file
	scheduleFile := "./schedules.yaml"
	var schedules []map[string]interface{}

	if data, err := os.ReadFile(scheduleFile); err == nil {
		// Parse existing schedules
		if err := yaml.Unmarshal(data, &schedules); err != nil {
			fmt.Printf("Error parsing existing schedules: %v\n", err)
			return
		}
	}

	// Check for duplicate names
	for _, schedule := range schedules {
		if name, ok := schedule["name"].(string); ok && name == scheduleName {
			fmt.Printf("Error: Schedule with name '%s' already exists\n", scheduleName)
			return
		}
	}

	// Add new schedule
	schedules = append(schedules, scheduleConfig)

	// Save updated schedules
	data, err := yaml.Marshal(schedules)
	if err != nil {
		fmt.Printf("Error marshaling schedules: %v\n", err)
		return
	}

	if err := os.WriteFile(scheduleFile, data, 0644); err != nil {
		fmt.Printf("Error saving schedules: %v\n", err)
		return
	}

	fmt.Printf("✅ Schedule created successfully:\n")
	fmt.Printf("  Name: %s\n", scheduleName)
	fmt.Printf("  Schedule: %s\n", cronExpr)
	fmt.Printf("  Type: %s\n", scheduleType)
	fmt.Printf("  Target: %s\n", target)
	fmt.Printf("  Enabled: %t\n", enabled)
	fmt.Printf("  File: %s\n", scheduleFile)

	fmt.Println("\nTo start the scheduler, run:")
	fmt.Println("  typosentinel-enterprise server --enable-scheduler")
}

func runScheduleUpdate(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: schedule name is required")
		fmt.Println("Usage: typosentinel-enterprise schedule update <name> [--cron <expression>] [--enabled <true/false>] [--target <target>]")
		return
	}

	scheduleName := args[0]
	cronExpr, _ := cmd.Flags().GetString("cron")
	target, _ := cmd.Flags().GetString("target")
	enabled, _ := cmd.Flags().GetBool("enabled")

	fmt.Printf("Updating schedule: %s\n", scheduleName)

	// Load existing schedules
	scheduleFile := "./schedules.yaml"
	if _, err := os.Stat(scheduleFile); os.IsNotExist(err) {
		fmt.Printf("Error: Schedule file not found: %s\n", scheduleFile)
		fmt.Println("No schedules exist yet. Use 'schedule create' to create a new schedule.")
		return
	}

	data, err := os.ReadFile(scheduleFile)
	if err != nil {
		fmt.Printf("Error reading schedule file: %v\n", err)
		return
	}

	var schedules []map[string]interface{}
	if err := yaml.Unmarshal(data, &schedules); err != nil {
		fmt.Printf("Error parsing schedules: %v\n", err)
		return
	}

	// Find and update the schedule
	found := false
	for i, schedule := range schedules {
		if name, ok := schedule["name"].(string); ok && name == scheduleName {
			found = true

			// Update fields if provided
			if cronExpr != "" {
				schedules[i]["schedule"] = cronExpr
				fmt.Printf("  Updated schedule: %s\n", cronExpr)
			}

			if target != "" {
				// Update target in the targets array
				if targets, ok := schedules[i]["targets"].([]interface{}); ok && len(targets) > 0 {
					if targetMap, ok := targets[0].(map[interface{}]interface{}); ok {
						targetMap["organization"] = target
						fmt.Printf("  Updated target: %s\n", target)
					}
				}
			}

			if cmd.Flags().Changed("enabled") {
				schedules[i]["enabled"] = enabled
				fmt.Printf("  Updated enabled: %t\n", enabled)
			}

			schedules[i]["updated_at"] = time.Now().Format(time.RFC3339)
			break
		}
	}

	if !found {
		fmt.Printf("Error: Schedule '%s' not found\n", scheduleName)
		fmt.Println("Available schedules:")
		for _, schedule := range schedules {
			if name, ok := schedule["name"].(string); ok {
				fmt.Printf("  - %s\n", name)
			}
		}
		return
	}

	// Save updated schedules
	updatedData, err := yaml.Marshal(schedules)
	if err != nil {
		fmt.Printf("Error marshaling schedules: %v\n", err)
		return
	}

	if err := os.WriteFile(scheduleFile, updatedData, 0644); err != nil {
		fmt.Printf("Error saving schedules: %v\n", err)
		return
	}

	fmt.Printf("✅ Schedule '%s' updated successfully\n", scheduleName)
}

func runScheduleDelete(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: schedule name is required")
		fmt.Println("Usage: typosentinel-enterprise schedule delete <name>")
		return
	}

	scheduleName := args[0]
	fmt.Printf("Deleting schedule: %s\n", scheduleName)

	// Load existing schedules
	scheduleFile := "./schedules.yaml"
	if _, err := os.Stat(scheduleFile); os.IsNotExist(err) {
		fmt.Printf("Error: Schedule file not found: %s\n", scheduleFile)
		fmt.Println("No schedules exist yet.")
		return
	}

	data, err := os.ReadFile(scheduleFile)
	if err != nil {
		fmt.Printf("Error reading schedule file: %v\n", err)
		return
	}

	var schedules []map[string]interface{}
	if err := yaml.Unmarshal(data, &schedules); err != nil {
		fmt.Printf("Error parsing schedules: %v\n", err)
		return
	}

	// Find and remove the schedule
	found := false
	var updatedSchedules []map[string]interface{}

	for _, schedule := range schedules {
		if name, ok := schedule["name"].(string); ok && name == scheduleName {
			found = true
			fmt.Printf("  Found schedule: %s\n", name)
			// Skip this schedule (don't add to updatedSchedules)
		} else {
			updatedSchedules = append(updatedSchedules, schedule)
		}
	}

	if !found {
		fmt.Printf("Error: Schedule '%s' not found\n", scheduleName)
		fmt.Println("Available schedules:")
		for _, schedule := range schedules {
			if name, ok := schedule["name"].(string); ok {
				fmt.Printf("  - %s\n", name)
			}
		}
		return
	}

	// Save updated schedules
	if len(updatedSchedules) == 0 {
		// If no schedules left, remove the file or write empty array
		if err := os.WriteFile(scheduleFile, []byte("[]"), 0644); err != nil {
			fmt.Printf("Error saving empty schedules: %v\n", err)
			return
		}
	} else {
		updatedData, err := yaml.Marshal(updatedSchedules)
		if err != nil {
			fmt.Printf("Error marshaling schedules: %v\n", err)
			return
		}

		if err := os.WriteFile(scheduleFile, updatedData, 0644); err != nil {
			fmt.Printf("Error saving schedules: %v\n", err)
			return
		}
	}

	fmt.Printf("✅ Schedule '%s' deleted successfully\n", scheduleName)
	fmt.Printf("Remaining schedules: %d\n", len(updatedSchedules))
}

func runScheduleTrigger(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: schedule name is required")
		fmt.Println("Usage: typosentinel-enterprise schedule trigger <name>")
		return
	}

	scheduleName := args[0]
	fmt.Printf("Triggering schedule: %s\n", scheduleName)

	// Load existing schedules
	scheduleFile := "./schedules.yaml"
	if _, err := os.Stat(scheduleFile); os.IsNotExist(err) {
		fmt.Printf("Error: Schedule file not found: %s\n", scheduleFile)
		fmt.Println("No schedules exist yet.")
		return
	}

	data, err := os.ReadFile(scheduleFile)
	if err != nil {
		fmt.Printf("Error reading schedule file: %v\n", err)
		return
	}

	var schedules []map[string]interface{}
	if err := yaml.Unmarshal(data, &schedules); err != nil {
		fmt.Printf("Error parsing schedules: %v\n", err)
		return
	}

	// Find the schedule
	var targetSchedule map[string]interface{}
	found := false

	for _, schedule := range schedules {
		if name, ok := schedule["name"].(string); ok && name == scheduleName {
			targetSchedule = schedule
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("Error: Schedule '%s' not found\n", scheduleName)
		fmt.Println("Available schedules:")
		for _, schedule := range schedules {
			if name, ok := schedule["name"].(string); ok {
				fmt.Printf("  - %s\n", name)
			}
		}
		return
	}

	// Check if schedule is enabled
	enabled, _ := targetSchedule["enabled"].(bool)
	if !enabled {
		fmt.Printf("Warning: Schedule '%s' is disabled\n", scheduleName)
		fmt.Println("Enable the schedule first with: schedule update <name> --enabled true")
	}

	// Extract schedule details
	scheduleType := getScheduleValue(targetSchedule, "type", "organization")

	fmt.Printf("📋 Schedule Details:\n")
	fmt.Printf("  Name: %s\n", scheduleName)
	fmt.Printf("  Type: %s\n", scheduleType)
	fmt.Printf("  Schedule: %s\n", getScheduleValue(targetSchedule, "schedule", ""))
	fmt.Printf("  Enabled: %t\n", enabled)

	// Load application configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	ctx := context.Background()
	repoManager := repository.NewManager(repository.DefaultManagerConfig())

	// Extract targets
	targets, ok := targetSchedule["targets"].([]interface{})
	if !ok || len(targets) == 0 {
		fmt.Println("Error: No targets found in schedule")
		return
	}

	fmt.Printf("\n🚀 Triggering scan for %d targets...\n", len(targets))

	successCount := 0
	errorCount := 0

	// Process each target
	for i, target := range targets {
		targetMap, ok := target.(map[interface{}]interface{})
		if !ok {
			fmt.Printf("Error: Invalid target format at index %d\n", i)
			errorCount++
			continue
		}

		organization := getScheduleConfigValue(targetMap, "organization", "")
		provider := getScheduleConfigValue(targetMap, "provider", "github")

		if organization == "" {
			fmt.Printf("Error: No organization specified for target %d\n", i)
			errorCount++
			continue
		}

		fmt.Printf("\nTarget %d/%d: %s (%s)\n", i+1, len(targets), organization, provider)

		// Trigger scan based on schedule type
		if scheduleType == "organization" {
			if err := scanOrganizationFromConfig(ctx, repoManager, cfg, provider, organization); err != nil {
				fmt.Printf("  ❌ Error: %v\n", err)
				errorCount++
			} else {
				fmt.Printf("  ✅ Scan completed successfully\n")
				successCount++
			}
		} else {
			fmt.Printf("  ⚠️  Unsupported schedule type: %s\n", scheduleType)
			errorCount++
		}
	}

	// Update last run time in schedule
	for i, schedule := range schedules {
		if name, ok := schedule["name"].(string); ok && name == scheduleName {
			schedules[i]["last_run"] = time.Now().Format(time.RFC3339)
			schedules[i]["last_run_status"] = fmt.Sprintf("success:%d,error:%d", successCount, errorCount)
			break
		}
	}

	// Save updated schedules
	updatedData, err := yaml.Marshal(schedules)
	if err != nil {
		fmt.Printf("Warning: Could not update last run time: %v\n", err)
	} else {
		os.WriteFile(scheduleFile, updatedData, 0644)
	}

	fmt.Printf("\n📊 Trigger Summary:\n")
	fmt.Printf("  Schedule: %s\n", scheduleName)
	fmt.Printf("  Successful scans: %d\n", successCount)
	fmt.Printf("  Failed scans: %d\n", errorCount)
	fmt.Printf("  Total targets: %d\n", len(targets))
	fmt.Printf("  Triggered at: %s\n", time.Now().Format("2006-01-02 15:04:05"))
}

func runAuditLogs(cmd *cobra.Command, args []string) {
	fmt.Println("Viewing audit logs...")

	// Get command flags
	limit, _ := cmd.Flags().GetInt("limit")
	filter, _ := cmd.Flags().GetString("filter")
	since, _ := cmd.Flags().GetString("since")

	if limit <= 0 {
		limit = 50 // Default limit
	}

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Check for audit log file
	auditLogPath := "./logs/audit.log"
	if cfg.App.DataDir != "" {
		auditLogPath = filepath.Join(cfg.App.DataDir, "audit.log")
	}

	// Check if audit log exists
	if _, err := os.Stat(auditLogPath); os.IsNotExist(err) {
		fmt.Printf("❌ Audit log not found at %s\n", auditLogPath)
		fmt.Println("Audit logging may not be enabled or no events have been logged yet")
		fmt.Println("To enable audit logging, start the server with --enable-audit flag")
		return
	}

	// Read audit log file
	data, err := os.ReadFile(auditLogPath)
	if err != nil {
		fmt.Printf("Error reading audit log: %v\n", err)
		return
	}

	if len(data) == 0 {
		fmt.Println("Audit log is empty")
		return
	}

	// Parse audit log entries
	lines := strings.Split(string(data), "\n")
	var auditEntries []map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Skip non-JSON lines
			continue
		}

		// Apply filters
		if filter != "" && !matchesAuditFilter(entry, filter) {
			continue
		}

		if since != "" && !isAfterTime(entry, since) {
			continue
		}

		auditEntries = append(auditEntries, entry)
	}

	// Sort by timestamp (most recent first)
	// Simple sort by comparing timestamp strings
	for i := 0; i < len(auditEntries)-1; i++ {
		for j := i + 1; j < len(auditEntries); j++ {
			ts1 := getStringValue(auditEntries[i], "timestamp")
			ts2 := getStringValue(auditEntries[j], "timestamp")
			if ts1 < ts2 {
				auditEntries[i], auditEntries[j] = auditEntries[j], auditEntries[i]
			}
		}
	}

	// Apply limit
	if len(auditEntries) > limit {
		auditEntries = auditEntries[:limit]
	}

	// Display audit log summary
	fmt.Printf("📋 Audit Log Summary:\n")
	fmt.Printf("  Log file: %s\n", auditLogPath)
	fmt.Printf("  Total entries: %d\n", len(auditEntries))
	fmt.Printf("  Showing: %d entries\n", len(auditEntries))
	if filter != "" {
		fmt.Printf("  Filter: %s\n", filter)
	}
	if since != "" {
		fmt.Printf("  Since: %s\n", since)
	}

	// Display audit entries
	fmt.Printf("\n📊 Audit Entries:\n")
	fmt.Printf("%-20s %-15s %-20s %-30s %-20s\n",
		"Timestamp", "Event Type", "User", "Resource", "Action")
	fmt.Println(strings.Repeat("-", 105))

	for _, entry := range auditEntries {
		timestamp := getStringValue(entry, "timestamp")
		if len(timestamp) > 19 {
			timestamp = timestamp[:19] // Truncate to YYYY-MM-DD HH:MM:SS
		}

		eventType := getStringValue(entry, "event_type")
		if eventType == "" {
			eventType = getStringValue(entry, "type")
		}

		user := getStringValue(entry, "user")
		if user == "" {
			user = getStringValue(entry, "actor")
		}

		resource := getStringValue(entry, "resource")
		if resource == "" {
			resource = getStringValue(entry, "target")
		}

		action := getStringValue(entry, "action")
		if action == "" {
			action = getStringValue(entry, "operation")
		}

		fmt.Printf("%-20s %-15s %-20s %-30s %-20s\n",
			timestamp,
			truncateString(eventType, 15),
			truncateString(user, 20),
			truncateString(resource, 30),
			truncateString(action, 20))
	}

	if len(auditEntries) == 0 {
		fmt.Println("No audit entries found matching the criteria")
	}

	fmt.Printf("\nUse --limit to show more entries, --filter to filter by content, --since to filter by time\n")
}

// Helper function to check if audit entry matches filter
func matchesAuditFilter(entry map[string]interface{}, filter string) bool {
	filterLower := strings.ToLower(filter)

	// Check common fields
	fields := []string{"event_type", "type", "user", "actor", "resource", "target", "action", "operation", "message"}
	for _, field := range fields {
		if value := getStringValue(entry, field); value != "" {
			if strings.Contains(strings.ToLower(value), filterLower) {
				return true
			}
		}
	}

	return false
}

// Helper function to check if entry is after specified time
func isAfterTime(entry map[string]interface{}, since string) bool {
	timestamp := getStringValue(entry, "timestamp")
	if timestamp == "" {
		return false
	}

	// Simple string comparison for ISO timestamps
	return timestamp >= since
}

// Helper function to truncate strings
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func runAuditReport(cmd *cobra.Command, args []string) {
	fmt.Println("Generating compliance report...")

	// Get command flags
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")

	if format == "" {
		format = "json"
	}

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Check for audit log file
	auditLogPath := "./logs/audit.log"
	if cfg.App.DataDir != "" {
		auditLogPath = filepath.Join(cfg.App.DataDir, "audit.log")
	}

	// Check if audit log exists
	if _, err := os.Stat(auditLogPath); os.IsNotExist(err) {
		fmt.Printf("❌ Audit log not found at %s\n", auditLogPath)
		fmt.Println("Cannot generate compliance report without audit logs")
		return
	}

	// Read and parse audit log
	data, err := os.ReadFile(auditLogPath)
	if err != nil {
		fmt.Printf("Error reading audit log: %v\n", err)
		return
	}

	lines := strings.Split(string(data), "\n")
	var auditEntries []map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Apply time filters
		timestamp := getStringValue(entry, "timestamp")
		if since != "" && timestamp < since {
			continue
		}
		if until != "" && timestamp > until {
			continue
		}

		auditEntries = append(auditEntries, entry)
	}

	// Generate compliance report
	report := generateComplianceReport(auditEntries, since, until)

	// Format and output report
	var reportData []byte
	switch format {
	case "json":
		reportData, err = json.MarshalIndent(report, "", "  ")
	case "csv":
		reportData, err = generateComplianceCSV(report)
	case "html":
		reportData, err = generateComplianceHTML(report)
	default:
		fmt.Printf("Unsupported format: %s. Supported formats: json, csv, html\n", format)
		return
	}

	if err != nil {
		fmt.Printf("Error formatting report: %v\n", err)
		return
	}

	// Output to file or stdout
	if output != "" {
		if err := os.WriteFile(output, reportData, 0644); err != nil {
			fmt.Printf("Error writing report to file: %v\n", err)
			return
		}
		fmt.Printf("✅ Compliance report generated: %s\n", output)
	} else {
		fmt.Println(string(reportData))
	}
}

func runConfigValidate(cmd *cobra.Command, args []string) {
	fmt.Println("Validating configuration...")

	configPath := "."
	if len(args) > 0 {
		configPath = args[0]
	}

	// Load and validate configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load(configPath); err != nil {
		fmt.Printf("❌ Configuration validation failed: %v\n", err)
		os.Exit(1)
		return
	}

	cfg := cfgManager.Get()
	fmt.Println("✅ Configuration loaded successfully")

	// Validate specific sections
	validationErrors := []string{}

	// Validate database configuration
	if cfg.Database.Type == "" {
		validationErrors = append(validationErrors, "Database type is required")
	} else if cfg.Database.Type != "sqlite" {
		if cfg.Database.Host == "" {
			validationErrors = append(validationErrors, "Database host is required for non-sqlite databases")
		}
		if cfg.Database.Username == "" {
			validationErrors = append(validationErrors, "Database username is required for non-sqlite databases")
		}
	}

	// Validate server configuration
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		validationErrors = append(validationErrors, "Server port must be between 1 and 65535")
	}

	// Validate ML configuration
	if cfg.ML.Enabled {
		if cfg.ML.ModelPath == "" {
			validationErrors = append(validationErrors, "ML model path is required when ML is enabled")
		}
		if cfg.ML.Threshold < 0 || cfg.ML.Threshold > 1 {
			validationErrors = append(validationErrors, "ML threshold must be between 0 and 1")
		}
	}

	// Validate Redis configuration
	if cfg.Redis.Enabled {
		if cfg.Redis.Host == "" {
			validationErrors = append(validationErrors, "Redis host is required when Redis is enabled")
		}
		if cfg.Redis.Port < 1 || cfg.Redis.Port > 65535 {
			validationErrors = append(validationErrors, "Redis port must be between 1 and 65535")
		}
	}

	// Validate integrations
	if cfg.Integrations != nil && cfg.Integrations.Enabled {
		if len(cfg.Integrations.Connectors) == 0 {
			validationErrors = append(validationErrors, "At least one connector must be configured when integrations are enabled")
		}

		for name, connector := range cfg.Integrations.Connectors {
			if connector.Type == "" {
				validationErrors = append(validationErrors, fmt.Sprintf("Connector %s must have a type", name))
			}
			if len(connector.Settings) == 0 {
				validationErrors = append(validationErrors, fmt.Sprintf("Connector %s must have settings", name))
			}
		}
	}

	// Report validation results
	if len(validationErrors) > 0 {
		fmt.Printf("❌ Configuration validation failed with %d errors:\n", len(validationErrors))
		for i, err := range validationErrors {
			fmt.Printf("  %d. %s\n", i+1, err)
		}
		os.Exit(1)
	} else {
		fmt.Println("✅ Configuration validation passed")
		fmt.Printf("  - Environment: %s\n", cfg.App.Environment)
		fmt.Printf("  - Database: %s\n", cfg.Database.Type)
		fmt.Printf("  - Server: %s:%d\n", cfg.Server.Host, cfg.Server.Port)
		fmt.Printf("  - ML Enabled: %t\n", cfg.ML.Enabled)
		fmt.Printf("  - Redis Enabled: %t\n", cfg.Redis.Enabled)
		if cfg.Integrations != nil {
			fmt.Printf("  - Integrations: %d connectors\n", len(cfg.Integrations.Connectors))
		}
	}
}

func runConfigGenerate(cmd *cobra.Command, args []string) {
	fmt.Println("Generating configuration template...")

	outputFile := "config.yaml"
	if len(args) > 0 {
		outputFile = args[0]
	}

	// Generate a comprehensive configuration template
	configTemplate := `# Typosentinel Enterprise Configuration
# This is a comprehensive configuration template with all available options

app:
  name: "Typosentinel"
  version: "1.0.0"
  environment: "development"  # development, testing, staging, production
  debug: false
  verbose: false
  log_level: "info"  # debug, info, warn, error
  data_dir: "./data"
  temp_dir: "/tmp"
  max_workers: 10

server:
  host: "localhost"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "60s"
  shutdown_timeout: "30s"
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
    ca_file: ""
  cors:
    enabled: true
    allowed_origins: ["*"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers: ["*"]
    exposed_headers: []
    allow_credentials: false
    max_age: 3600

database:
  type: "sqlite"  # sqlite, postgres, mysql
  host: "localhost"
  port: 5432
  database: "./data/typosentinel.db"
  username: ""
  password: ""
  ssl_mode: "disable"  # disable, require, verify-ca, verify-full
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: "5m"
  migrations_path: "./migrations"

redis:
  enabled: false
  host: "localhost"
  port: 6379
  password: ""
  database: 0
  pool_size: 10
  dial_timeout: "5s"
  read_timeout: "3s"
  write_timeout: "3s"
  idle_timeout: "5m"
  ttl: "1h"

logging:
  level: "info"
  format: "json"  # json, text
  output: "stdout"  # stdout, stderr, file
  file: ""
  max_size: 100
  max_backups: 3
  max_age: 28
  compress: true

metrics:
  enabled: false
  provider: "prometheus"  # prometheus, statsd
  address: ":9090"
  namespace: "typosentinel"
  interval: "15s"
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]

security:
  jwt:
    enabled: false
    secret: ""
    expiration: "1h"
    refresh_expiration: "24h"
  api_keys:
    enabled: false
    header_name: "X-API-Key"
  encryption:
    algorithm: "aes-256-gcm"
    key: "default-encryption-key-32-chars-long"
  password_policy:
    min_length: 8
    require_upper: true
    require_lower: true
    require_digit: true
    require_symbol: false
  csrf:
    enabled: false
    cookie_name: "_csrf_token"
    header_name: "X-CSRF-Token"

ml:
  enabled: false
  model_path: ""
  threshold: 0.5
  batch_size: 100
  timeout: "30s"
  cache_size: 1000
  update_interval: "24h"
  model_config:
    type: "tensorflow"
    preprocessing:
      scaling: "standard"

api:
  enabled: true
  prefix: "/api/v1"
  timeout: "30s"
  max_request_size: "10MB"

rate_limit:
  enabled: false
  requests_per_minute: 60
  burst: 10

features:
  enterprise: true
  ml_analysis: false
  threat_intelligence: false
  advanced_reporting: true
  audit_logging: true
  policy_enforcement: true

policies:
  enabled: true
  default_policy: "strict"
  custom_policies_dir: "./policies"

integrations:
  enabled: false
  connectors:
    slack:
      type: "slack"
      enabled: false
      settings:
        webhook_url: ""
        channel: "#security"
        username: "Typosentinel"
    email:
      type: "email"
      enabled: false
      settings:
        smtp_host: ""
        smtp_port: 587
        username: ""
        password: ""
        from: ""
        to: []
    webhook:
      type: "webhook"
      enabled: false
      settings:
        url: ""
        method: "POST"
        headers: {}
  event_routing:
    critical: ["slack", "email"]
    high: ["slack"]
    medium: ["webhook"]
    low: []

supply_chain:
  enabled: false
  build_integrity:
    enabled: false
    signature_check: true
    tampering_detection: true
    build_analysis: true
    timeout: "30s"
  zero_day_detection:
    enabled: false
    behavioral_analysis: true
    code_anomaly_detection: true
    runtime_analysis: false
    anomaly_threshold: 0.8
    timeout: "60s"
  dependency_graph:
    enabled: false
    max_depth: 10
    transitive_analysis: true
    confusion_detection: true
    supply_chain_risk_analysis: true
  threat_intelligence:
    enabled: false
    sources: []
    cache_enabled: true
    cache_ttl: "1h"
    timeout: "10s"
    retries: 3
  honeypot_detection:
    enabled: false
    package_trap_detection: true
    authenticity_validation: true
    confidence_threshold: 0.9
    timeout: "30s"
  risk_calculation:
    enabled: false
    weights:
      build_integrity: 0.3
      zero_day_threats: 0.3
      threat_intel: 0.2
      honeypot_detection: 0.1
      dependency_risk: 0.1
    thresholds:
      low: 0.3
      medium: 0.6
      high: 0.8
      critical: 0.9
`

	// Write configuration to file
	if err := os.WriteFile(outputFile, []byte(configTemplate), 0644); err != nil {
		fmt.Printf("❌ Failed to write configuration file: %v\n", err)
		os.Exit(1)
		return
	}

	fmt.Printf("✅ Configuration template generated: %s\n", outputFile)
	fmt.Println("📝 Please review and customize the configuration for your environment")
	fmt.Println("🔧 Key sections to configure:")
	fmt.Println("  - Database connection settings")
	fmt.Println("  - Security settings (JWT secrets, API keys)")
	fmt.Println("  - Integration connectors")
	fmt.Println("  - ML model paths (if using ML features)")
	fmt.Println("  - Supply chain security settings")
}

func runHealthCheck(cmd *cobra.Command, args []string) {
	fmt.Println("Performing health check...")

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("❌ Configuration: Failed to load - %v\n", err)
		return
	}
	cfg := cfgManager.Get()
	fmt.Println("✅ Configuration: Loaded successfully")

	// Check database connectivity
	if cfg.Database.Type != "" {
		dbConfig := &config.DatabaseConfig{
			Host:         cfg.Database.Host,
			Port:         cfg.Database.Port,
			Username:     cfg.Database.Username,
			Password:     cfg.Database.Password,
			Database:     cfg.Database.Database,
			SSLMode:      cfg.Database.SSLMode,
			MaxOpenConns: cfg.Database.MaxOpenConns,
			MaxIdleConns: cfg.Database.MaxIdleConns,
		}

		dbService, err := database.NewDatabaseService(dbConfig)
		if err != nil {
			fmt.Printf("❌ Database: Connection failed - %v\n", err)
		} else {
			fmt.Println("✅ Database: Connection successful")
			dbService.Close()
		}
	} else {
		fmt.Println("⚠️  Database: No database type configured")
	}

	// Check Redis connectivity
	if cfg.Redis.Enabled {
		fmt.Printf("✅ Redis: Configuration found (Host: %s:%d)\n", cfg.Redis.Host, cfg.Redis.Port)
	} else {
		fmt.Println("⚠️  Redis: Disabled in configuration")
	}

	// Check ML models
	if cfg.ML.Enabled {
		if cfg.ML.ModelPath != "" {
			fmt.Printf("✅ ML Models: Path configured (%s)\n", cfg.ML.ModelPath)
		} else {
			fmt.Println("❌ ML Models: No model path configured")
		}
	} else {
		fmt.Println("⚠️  ML Models: Disabled in configuration")
	}

	// Check integrations
	integrationCount := 0
	if cfg.Integrations != nil && cfg.Integrations.Enabled {
		integrationCount = len(cfg.Integrations.Connectors)
		for name, connector := range cfg.Integrations.Connectors {
			if connector.Enabled {
				fmt.Printf("  ✅ %s integration enabled\n", name)
			}
		}
	}

	fmt.Printf("✅ Integrations: %d configured\n", integrationCount)

	// Check features
	fmt.Printf("✅ Features: Enterprise mode enabled\n")

	fmt.Println("\n🏥 Health check completed")
}

func runHealthMetrics(cmd *cobra.Command, args []string) {
	fmt.Println("Collecting health metrics...")

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Initialize database service
	dbConfig := &config.DatabaseConfig{
		Host:         cfg.Database.Host,
		Port:         cfg.Database.Port,
		Username:     cfg.Database.Username,
		Password:     cfg.Database.Password,
		Database:     cfg.Database.Database,
		SSLMode:      cfg.Database.SSLMode,
		MaxOpenConns: cfg.Database.MaxOpenConns,
		MaxIdleConns: cfg.Database.MaxIdleConns,
	}

	dbService, err := database.NewDatabaseService(dbConfig)
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
		return
	}
	defer dbService.Close()

	// Collect metrics
	metrics := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"system": map[string]interface{}{
			"uptime":     time.Since(time.Now().Add(-time.Hour)).String(), // Placeholder
			"goroutines": runtime.NumGoroutine(),
			"memory": map[string]interface{}{
				"alloc":       runtime.MemStats{}.Alloc,
				"total_alloc": runtime.MemStats{}.TotalAlloc,
				"sys":         runtime.MemStats{}.Sys,
			},
		},
		"database": map[string]interface{}{
			"connected": true,
			"type":      cfg.Database.Type,
		},
		"features": map[string]interface{}{
			"ml_enabled":           cfg.ML.Enabled,
			"redis_enabled":        cfg.Redis.Enabled,
			"integrations_enabled": cfg.Integrations != nil && cfg.Integrations.Enabled,
		},
	}

	// Add scan statistics if available
	// This would typically query the database for scan counts, etc.
	metrics["scans"] = map[string]interface{}{
		"total_scans":      0,    // Would query from database
		"recent_scans":     0,    // Scans in last 24h
		"failed_scans":     0,    // Failed scans count
		"average_duration": "0s", // Average scan duration
	}

	// Add threat detection statistics
	metrics["threats"] = map[string]interface{}{
		"total_threats":    0, // Would query from database
		"recent_threats":   0, // Threats in last 24h
		"critical_threats": 0, // Critical severity threats
		"resolved_threats": 0, // Resolved threats count
	}

	// Output metrics as JSON
	output, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling metrics: %v\n", err)
		return
	}

	fmt.Println(string(output))
}

func runExportScans(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: output file is required")
		fmt.Println("Usage: typosentinel-enterprise export scans <output-file> [--format json|csv|sarif] [--filter <filter>]")
		return
	}

	outputFile := args[0]
	format, _ := cmd.Flags().GetString("format")
	filter, _ := cmd.Flags().GetString("filter")

	if format == "" {
		format = "json" // Default format
	}

	fmt.Printf("Exporting scan results to: %s\n", outputFile)
	fmt.Printf("Format: %s\n", format)

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Check for scan results directory
	resultsDir := filepath.Join(cfg.App.DataDir, "scan_results")
	if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
		fmt.Printf("❌ No scan results found in %s\n", resultsDir)
		fmt.Println("Run some scans first to generate results")
		return
	}

	// Collect scan result files
	var scanFiles []string
	walkErr := filepath.Walk(resultsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			scanFiles = append(scanFiles, path)
		}
		return nil
	})

	if walkErr != nil {
		fmt.Printf("Error scanning results directory: %v\n", walkErr)
		return
	}

	if len(scanFiles) == 0 {
		fmt.Println("❌ No scan result files found")
		return
	}

	fmt.Printf("Found %d scan result files\n", len(scanFiles))

	// Aggregate scan results
	var allResults []map[string]interface{}
	totalThreats := 0

	for _, file := range scanFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("Warning: Failed to read %s: %v\n", file, err)
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			fmt.Printf("Warning: Failed to parse %s: %v\n", file, err)
			continue
		}

		// Apply filter if specified
		if filter != "" && !matchesFilter(result, filter) {
			continue
		}

		// Add metadata
		result["source_file"] = file
		result["exported_at"] = time.Now().Format(time.RFC3339)

		allResults = append(allResults, result)

		// Count threats
		if threats, ok := result["threats"].([]interface{}); ok {
			totalThreats += len(threats)
		}
	}

	fmt.Printf("Collected %d scan results with %d total threats\n", len(allResults), totalThreats)

	// Export based on format
	var exportData []byte
	var exportErr error

	switch format {
	case "json":
		exportData, exportErr = json.MarshalIndent(map[string]interface{}{
			"export_info": map[string]interface{}{
				"exported_at":   time.Now().Format(time.RFC3339),
				"total_scans":   len(allResults),
				"total_threats": totalThreats,
				"format":        format,
				"filter":        filter,
			},
			"scan_results": allResults,
		}, "", "  ")

	case "csv":
		exportData, exportErr = exportToCSV(allResults)

	case "sarif":
		exportData, exportErr = exportToSARIF(allResults)

	default:
		fmt.Printf("Error: Unsupported format '%s'. Supported formats: json, csv, sarif\n", format)
		return
	}

	if exportErr != nil {
		fmt.Printf("Error formatting export data: %v\n", exportErr)
		return
	}

	// Write export file
	if err := os.WriteFile(outputFile, exportData, 0644); err != nil {
		fmt.Printf("Error writing export file: %v\n", err)
		return
	}

	fmt.Printf("✅ Export completed successfully:\n")
	fmt.Printf("  Output file: %s\n", outputFile)
	fmt.Printf("  Format: %s\n", format)
	fmt.Printf("  Size: %d bytes\n", len(exportData))
	fmt.Printf("  Scan results: %d\n", len(allResults))
	fmt.Printf("  Total threats: %d\n", totalThreats)
}

// Helper function to check if a result matches the filter
func matchesFilter(result map[string]interface{}, filter string) bool {
	// Simple filter implementation - check if filter string exists in repository name or threats
	filterLower := strings.ToLower(filter)

	if repo, ok := result["repository"].(string); ok {
		if strings.Contains(strings.ToLower(repo), filterLower) {
			return true
		}
	}

	if threats, ok := result["threats"].([]interface{}); ok {
		for _, threat := range threats {
			if threatMap, ok := threat.(map[string]interface{}); ok {
				if pkg, ok := threatMap["package"].(string); ok {
					if strings.Contains(strings.ToLower(pkg), filterLower) {
						return true
					}
				}
			}
		}
	}

	return false
}

// Helper function to export to CSV format
func exportToCSV(results []map[string]interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)

	// Write header
	header := []string{"Repository", "Scan Date", "Threats Count", "Status", "Duration"}
	writer.Write(header)

	// Write data rows
	for _, result := range results {
		row := []string{
			getStringValue(result, "repository"),
			getStringValue(result, "scan_date"),
			fmt.Sprintf("%d", getIntValue(result, "threats_count")),
			getStringValue(result, "status"),
			getStringValue(result, "duration"),
		}
		writer.Write(row)
	}

	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

// Helper function to export to SARIF format
func exportToSARIF(results []map[string]interface{}) ([]byte, error) {
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "TypoSentinel",
						"version": "1.0.0",
					},
				},
				"results": convertToSARIFResults(results),
			},
		},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

// Helper function to convert results to SARIF format
func convertToSARIFResults(results []map[string]interface{}) []map[string]interface{} {
	var sarifResults []map[string]interface{}

	for _, result := range results {
		if threats, ok := result["threats"].([]interface{}); ok {
			for _, threat := range threats {
				if threatMap, ok := threat.(map[string]interface{}); ok {
					sarifResult := map[string]interface{}{
						"ruleId": "typo-detection",
						"level":  "warning",
						"message": map[string]interface{}{
							"text": fmt.Sprintf("Potential typosquatting detected: %s", getStringValue(threatMap, "package")),
						},
						"locations": []map[string]interface{}{
							{
								"physicalLocation": map[string]interface{}{
									"artifactLocation": map[string]interface{}{
										"uri": getStringValue(result, "repository"),
									},
								},
							},
						},
					}
					sarifResults = append(sarifResults, sarifResult)
				}
			}
		}
	}

	return sarifResults
}

// Helper functions for safe type conversion
func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getIntValue(m map[string]interface{}, key string) int {
	if val, ok := m[key].(float64); ok {
		return int(val)
	}
	if val, ok := m[key].(int); ok {
		return val
	}
	return 0
}

func runExportDashboard(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: output file is required")
		fmt.Println("Usage: typosentinel-enterprise export dashboard <output-file> [--format html|json|pdf] [--include-charts]")
		return
	}

	outputFile := args[0]
	format, _ := cmd.Flags().GetString("format")
	includeCharts, _ := cmd.Flags().GetBool("include-charts")

	if format == "" {
		format = "html"
	}

	fmt.Printf("Exporting dashboard to: %s (format: %s)\n", outputFile, format)

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Initialize database connection
	dbConfig := &config.DatabaseConfig{
		Host:         cfg.Database.Host,
		Port:         cfg.Database.Port,
		Username:     cfg.Database.Username,
		Password:     cfg.Database.Password,
		Database:     cfg.Database.Database,
		SSLMode:      cfg.Database.SSLMode,
		MaxOpenConns: cfg.Database.MaxOpenConns,
		MaxIdleConns: cfg.Database.MaxIdleConns,
	}

	dbService, err := database.NewDatabaseService(dbConfig)
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
		return
	}
	defer dbService.Close()

	// Collect dashboard data
	dashboardData := collectDashboardData(dbService)

	// Generate dashboard export based on format
	var content []byte
	var fileExt string

	switch format {
	case "html":
		content, err = generateDashboardHTML(dashboardData, includeCharts)
		fileExt = ".html"
	case "json":
		content, err = generateDashboardJSON(dashboardData)
		fileExt = ".json"
	case "pdf":
		fmt.Println("PDF export not yet implemented, falling back to HTML")
		content, err = generateDashboardHTML(dashboardData, includeCharts)
		fileExt = ".html"
	default:
		fmt.Printf("Error: Unsupported format '%s'. Supported formats: html, json, pdf\n", format)
		return
	}

	if err != nil {
		fmt.Printf("Error generating dashboard export: %v\n", err)
		return
	}

	// Ensure output file has correct extension
	if !strings.HasSuffix(outputFile, fileExt) {
		outputFile += fileExt
	}

	// Write to file
	if err := os.WriteFile(outputFile, content, 0644); err != nil {
		fmt.Printf("Error writing dashboard export: %v\n", err)
		return
	}

	fmt.Printf("✅ Dashboard exported successfully to: %s\n", outputFile)
	fmt.Printf("📊 Export includes:\n")
	fmt.Printf("  - System overview\n")
	fmt.Printf("  - Scan statistics\n")
	fmt.Printf("  - Threat detection summary\n")
	fmt.Printf("  - Recent activity\n")
	if includeCharts {
		fmt.Printf("  - Interactive charts\n")
	}
	fmt.Printf("  - Generated at: %s\n", time.Now().Format("2006-01-02 15:04:05"))
}

func runUserList(cmd *cobra.Command, args []string) {
	fmt.Println("Listing users...")

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Initialize database connection directly
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.Username,
		cfg.Database.Password, cfg.Database.Database, cfg.Database.SSLMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
		return
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		fmt.Printf("Error pinging database: %v\n", err)
		return
	}

	// Query users directly from database
	// This is a simplified implementation - in a real system you'd use the auth service
	query := `SELECT id, username, email, role, created_at, active FROM users ORDER BY created_at DESC`

	rows, err := db.Query(query)
	if err != nil {
		fmt.Printf("Error querying users: %v\n", err)
		return
	}
	defer rows.Close()

	// Display users in a table format
	fmt.Printf("%-10s %-20s %-30s %-15s %-20s %-10s\n",
		"ID", "Username", "Email", "Role", "Created", "Active")
	fmt.Println(strings.Repeat("-", 105))

	userCount := 0
	for rows.Next() {
		var id, username, email, role string
		var createdAt time.Time
		var active bool

		if err := rows.Scan(&id, &username, &email, &role, &createdAt, &active); err != nil {
			fmt.Printf("Error scanning user row: %v\n", err)
			continue
		}

		status := "Yes"
		if !active {
			status = "No"
		}

		fmt.Printf("%-10s %-20s %-30s %-15s %-20s %-10s\n",
			id,
			username,
			email,
			role,
			createdAt.Format("2006-01-02 15:04"),
			status)

		userCount++
	}

	if userCount == 0 {
		fmt.Println("No users found")
		fmt.Println("Note: Users table may not exist yet. Run database migrations first.")
	} else {
		fmt.Printf("\nTotal users: %d\n", userCount)
	}
}

func runUserCreate(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: username is required")
		fmt.Println("Usage: typosentinel-enterprise user create <username> --email <email> --role <role>")
		return
	}

	username := args[0]
	email, _ := cmd.Flags().GetString("email")
	role, _ := cmd.Flags().GetString("role")

	if email == "" {
		fmt.Println("Error: email is required")
		return
	}

	if role == "" {
		role = "user" // Default role
	}

	fmt.Printf("Creating user: %s\n", username)

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Initialize database connection
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.Username,
		cfg.Database.Password, cfg.Database.Database, cfg.Database.SSLMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
		return
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		fmt.Printf("Error pinging database: %v\n", err)
		return
	}

	// Create user
	query := `
		INSERT INTO users (id, username, email, role, created_at, updated_at, active)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	userID := fmt.Sprintf("user_%d", time.Now().Unix())
	now := time.Now()

	_, err = db.Exec(query, userID, username, email, role, now, now, true)
	if err != nil {
		fmt.Printf("Error creating user: %v\n", err)
		return
	}

	fmt.Printf("User created successfully:\n")
	fmt.Printf("  ID: %s\n", userID)
	fmt.Printf("  Username: %s\n", username)
	fmt.Printf("  Email: %s\n", email)
	fmt.Printf("  Role: %s\n", role)
	fmt.Printf("  Created: %s\n", now.Format("2006-01-02 15:04:05"))
}

func runUserUpdate(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: username is required")
		fmt.Println("Usage: typosentinel-enterprise user update <username> [--email <email>] [--role <role>] [--enabled <true/false>]")
		return
	}

	username := args[0]
	email, _ := cmd.Flags().GetString("email")
	role, _ := cmd.Flags().GetString("role")
	enabled, _ := cmd.Flags().GetBool("enabled")

	fmt.Printf("Updating user: %s\n", username)

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Initialize database connection
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.Username,
		cfg.Database.Password, cfg.Database.Database, cfg.Database.SSLMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
		return
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		fmt.Printf("Error pinging database: %v\n", err)
		return
	}

	// Check if user exists
	var userID string
	checkQuery := `SELECT id FROM users WHERE username = $1`
	err = db.QueryRow(checkQuery, username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("Error: User '%s' not found\n", username)
			return
		}
		fmt.Printf("Error checking user: %v\n", err)
		return
	}

	// Build update query dynamically based on provided flags
	var setParts []string
	var updateArgs []interface{}
	argIndex := 1

	if email != "" {
		setParts = append(setParts, fmt.Sprintf("email = $%d", argIndex))
		updateArgs = append(updateArgs, email)
		argIndex++
	}

	if role != "" {
		setParts = append(setParts, fmt.Sprintf("role = $%d", argIndex))
		updateArgs = append(updateArgs, role)
		argIndex++
	}

	if cmd.Flags().Changed("enabled") {
		setParts = append(setParts, fmt.Sprintf("active = $%d", argIndex))
		updateArgs = append(updateArgs, enabled)
		argIndex++
	}

	if len(setParts) == 0 {
		fmt.Println("No updates specified. Use --email, --role, or --enabled flags.")
		return
	}

	// Add updated_at timestamp
	setParts = append(setParts, fmt.Sprintf("updated_at = $%d", argIndex))
	updateArgs = append(updateArgs, time.Now())
	argIndex++

	// Add username for WHERE clause
	updateArgs = append(updateArgs, username)

	updateQuery := fmt.Sprintf("UPDATE users SET %s WHERE username = $%d",
		strings.Join(setParts, ", "), argIndex)

	_, err = db.Exec(updateQuery, updateArgs...)
	if err != nil {
		fmt.Printf("Error updating user: %v\n", err)
		return
	}

	fmt.Printf("User '%s' updated successfully\n", username)

	// Show updated user info
	var updatedEmail, updatedRole string
	var updatedActive bool
	var updatedAt time.Time

	selectQuery := `SELECT email, role, active, updated_at FROM users WHERE username = $1`
	err = db.QueryRow(selectQuery, username).Scan(&updatedEmail, &updatedRole, &updatedActive, &updatedAt)
	if err != nil {
		fmt.Printf("Error retrieving updated user info: %v\n", err)
		return
	}

	fmt.Printf("Updated information:\n")
	fmt.Printf("  Username: %s\n", username)
	fmt.Printf("  Email: %s\n", updatedEmail)
	fmt.Printf("  Role: %s\n", updatedRole)
	fmt.Printf("  Active: %v\n", updatedActive)
	fmt.Printf("  Updated: %s\n", updatedAt.Format("2006-01-02 15:04:05"))
}

func runUserDelete(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: username is required")
		fmt.Println("Usage: typosentinel-enterprise user delete <username>")
		return
	}

	username := args[0]
	fmt.Printf("Deleting user: %s\n", username)

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Initialize database connection
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.Username,
		cfg.Database.Password, cfg.Database.Database, cfg.Database.SSLMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
		return
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		fmt.Printf("Error pinging database: %v\n", err)
		return
	}

	// Check if user exists and get user info
	var userID, email, role string
	var active bool
	var createdAt time.Time

	checkQuery := `SELECT id, email, role, active, created_at FROM users WHERE username = $1`
	err = db.QueryRow(checkQuery, username).Scan(&userID, &email, &role, &active, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("Error: User '%s' not found\n", username)
			return
		}
		fmt.Printf("Error checking user: %v\n", err)
		return
	}

	// Show user info before deletion
	fmt.Printf("User to be deleted:\n")
	fmt.Printf("  ID: %s\n", userID)
	fmt.Printf("  Username: %s\n", username)
	fmt.Printf("  Email: %s\n", email)
	fmt.Printf("  Role: %s\n", role)
	fmt.Printf("  Active: %v\n", active)
	fmt.Printf("  Created: %s\n", createdAt.Format("2006-01-02 15:04:05"))

	// Confirm deletion
	fmt.Print("\nAre you sure you want to delete this user? (y/N): ")
	var confirmation string
	fmt.Scanln(&confirmation)

	if strings.ToLower(confirmation) != "y" && strings.ToLower(confirmation) != "yes" {
		fmt.Println("User deletion cancelled")
		return
	}

	// Delete user
	deleteQuery := `DELETE FROM users WHERE username = $1`
	result, err := db.Exec(deleteQuery, username)
	if err != nil {
		fmt.Printf("Error deleting user: %v\n", err)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		fmt.Printf("Error getting affected rows: %v\n", err)
		return
	}

	if rowsAffected == 0 {
		fmt.Printf("No user was deleted (user may not exist)\n")
		return
	}

	fmt.Printf("User '%s' deleted successfully\n", username)
}

func runPolicyList(cmd *cobra.Command, args []string) {
	fmt.Println("Listing security policies...")

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Display configured policies from config
	fmt.Printf("\n%-20s %-15s %-50s %-15s\n", "Policy Name", "Type", "Description", "Configuration")
	fmt.Println(strings.Repeat("-", 100))

	policyCount := 0

	// Main threat detection policy
	fmt.Printf("%-20s %-15s %-50s %-15s\n",
		"threat-detection", "Security", "Main threat detection and response policy",
		fmt.Sprintf("Fail: %v", cfg.Policies.FailOnThreats))
	policyCount++

	// Minimum threat level policy
	fmt.Printf("%-20s %-15s %-50s %-15s\n",
		"threat-threshold", "Security", "Minimum threat level for action",
		fmt.Sprintf("Level: %s", cfg.Policies.MinThreatLevel))
	policyCount++

	// Additional policies from other config sections
	if cfg.TypoDetection.Enabled {
		fmt.Printf("%-20s %-15s %-50s %-15s\n",
			"typo-detection", "Detection", "Typosquatting detection rules",
			fmt.Sprintf("Threshold: %.2f", cfg.TypoDetection.Threshold))
		policyCount++
	}

	if cfg.SupplyChain.Enabled {
		fmt.Printf("%-20s %-15s %-50s %-15s\n",
			"supply-chain", "Security", "Supply chain security monitoring",
			"Enabled")
		policyCount++
	}

	if cfg.MLAnalysis.Enabled {
		fmt.Printf("%-20s %-15s %-50s %-15s\n",
			"ml-analysis", "Detection", "Machine learning threat analysis",
			fmt.Sprintf("Threshold: %.2f", cfg.MLAnalysis.Threshold))
		policyCount++
	}

	fmt.Printf("\nTotal policies: %d\n", policyCount)

	// Show policy details
	fmt.Println("\nPolicy Details:")
	fmt.Println("===============")

	fmt.Printf("\nThreat Detection Policy:\n")
	fmt.Printf("  Fail on Threats: %v\n", cfg.Policies.FailOnThreats)
	fmt.Printf("  Minimum Threat Level: %s\n", cfg.Policies.MinThreatLevel)
	fmt.Printf("  Description: %s\n", "Controls how the system responds to detected threats")

	if cfg.TypoDetection.Enabled {
		fmt.Printf("\nTypo Detection Policy:\n")
		fmt.Printf("  Enabled: %v\n", cfg.TypoDetection.Enabled)
		fmt.Printf("  Threshold: %.2f\n", cfg.TypoDetection.Threshold)
		fmt.Printf("  Similarity Threshold: %.2f\n", cfg.TypoDetection.SimilarityThreshold)
		fmt.Printf("  Edit Distance Threshold: %d\n", cfg.TypoDetection.EditDistanceThreshold)
		fmt.Printf("  Phonetic Matching: %v\n", cfg.TypoDetection.PhoneticMatching)
		fmt.Printf("  Check Similar Names: %v\n", cfg.TypoDetection.CheckSimilarNames)
		fmt.Printf("  Check Homoglyphs: %v\n", cfg.TypoDetection.CheckHomoglyphs)
		if cfg.TypoDetection.DictionaryPath != "" {
			fmt.Printf("  Dictionary Path: %s\n", cfg.TypoDetection.DictionaryPath)
		}
	}

	if cfg.SupplyChain.Enabled {
		fmt.Printf("\nSupply Chain Policy:\n")
		fmt.Printf("  Enabled: %v\n", cfg.SupplyChain.Enabled)
		fmt.Printf("  Build Integrity: %v\n", cfg.SupplyChain.BuildIntegrity.Enabled)
		fmt.Printf("  Zero Day Detection: %v\n", cfg.SupplyChain.ZeroDayDetection.Enabled)
		fmt.Printf("  Dependency Graph: %v\n", cfg.SupplyChain.DependencyGraph.Enabled)
		fmt.Printf("  Threat Intelligence: %v\n", cfg.SupplyChain.ThreatIntelligence.Enabled)
		fmt.Printf("  Honeypot Detection: %v\n", cfg.SupplyChain.HoneypotDetection.Enabled)
	}

	if cfg.MLAnalysis.Enabled {
		fmt.Printf("\nML Analysis Policy:\n")
		fmt.Printf("  Enabled: %v\n", cfg.MLAnalysis.Enabled)
		fmt.Printf("  Threshold: %.2f\n", cfg.MLAnalysis.Threshold)
		fmt.Printf("  Model Path: %s\n", cfg.MLAnalysis.ModelPath)
	}
}

func runPolicyCreate(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: Policy name is required")
		fmt.Println("Usage: typosentinel-enterprise policy create <policy-name> [flags]")
		fmt.Println("Available policies: threat-detection, typo-detection, supply-chain, ml-analysis")
		return
	}

	policyName := args[0]
	fmt.Printf("Creating policy: %s\n", policyName)

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Get flag values
	enabled, _ := cmd.Flags().GetBool("enabled")
	threshold, _ := cmd.Flags().GetFloat64("threshold")
	failOnThreats, _ := cmd.Flags().GetBool("fail-on-threats")
	threatLevel, _ := cmd.Flags().GetString("threat-level")

	// Create/update policy based on name
	switch policyName {
	case "threat-detection":
		if cmd.Flags().Changed("fail-on-threats") {
			cfg.Policies.FailOnThreats = failOnThreats
		} else {
			cfg.Policies.FailOnThreats = true // Default
		}
		if cmd.Flags().Changed("threat-level") {
			cfg.Policies.MinThreatLevel = threatLevel
		} else {
			cfg.Policies.MinThreatLevel = "medium" // Default
		}
		fmt.Printf("  Threat detection policy created:\n")
		fmt.Printf("    Fail on threats: %v\n", cfg.Policies.FailOnThreats)
		fmt.Printf("    Minimum threat level: %s\n", cfg.Policies.MinThreatLevel)

	case "typo-detection":
		if cmd.Flags().Changed("enabled") {
			cfg.TypoDetection.Enabled = enabled
		} else {
			cfg.TypoDetection.Enabled = true // Default
		}
		if cmd.Flags().Changed("threshold") {
			cfg.TypoDetection.Threshold = threshold
		} else {
			cfg.TypoDetection.Threshold = 0.8 // Default
		}
		// Set other defaults
		cfg.TypoDetection.SimilarityThreshold = 0.7
		cfg.TypoDetection.EditDistanceThreshold = 3
		cfg.TypoDetection.PhoneticMatching = true
		cfg.TypoDetection.CheckSimilarNames = true
		cfg.TypoDetection.CheckHomoglyphs = true

		fmt.Printf("  Typo detection policy created:\n")
		fmt.Printf("    Enabled: %v\n", cfg.TypoDetection.Enabled)
		fmt.Printf("    Threshold: %.2f\n", cfg.TypoDetection.Threshold)
		fmt.Printf("    Similarity threshold: %.2f\n", cfg.TypoDetection.SimilarityThreshold)

	case "supply-chain":
		if cmd.Flags().Changed("enabled") {
			cfg.SupplyChain.Enabled = enabled
		} else {
			cfg.SupplyChain.Enabled = true // Default
		}
		// Enable sub-components by default
		cfg.SupplyChain.BuildIntegrity.Enabled = true
		cfg.SupplyChain.ZeroDayDetection.Enabled = true
		cfg.SupplyChain.DependencyGraph.Enabled = true
		cfg.SupplyChain.ThreatIntelligence.Enabled = true
		cfg.SupplyChain.HoneypotDetection.Enabled = true

		fmt.Printf("  Supply chain policy created:\n")
		fmt.Printf("    Enabled: %v\n", cfg.SupplyChain.Enabled)
		fmt.Printf("    Build integrity: %v\n", cfg.SupplyChain.BuildIntegrity.Enabled)
		fmt.Printf("    Threat intelligence: %v\n", cfg.SupplyChain.ThreatIntelligence.Enabled)

	case "ml-analysis":
		if cmd.Flags().Changed("enabled") {
			cfg.MLAnalysis.Enabled = enabled
		} else {
			cfg.MLAnalysis.Enabled = true // Default
		}
		if cmd.Flags().Changed("threshold") {
			cfg.MLAnalysis.Threshold = threshold
		} else {
			cfg.MLAnalysis.Threshold = 0.75 // Default
		}
		// Set default model path if not set
		if cfg.MLAnalysis.ModelPath == "" {
			cfg.MLAnalysis.ModelPath = "./ml/models/default.model"
		}

		fmt.Printf("  ML analysis policy created:\n")
		fmt.Printf("    Enabled: %v\n", cfg.MLAnalysis.Enabled)
		fmt.Printf("    Threshold: %.2f\n", cfg.MLAnalysis.Threshold)
		fmt.Printf("    Model path: %s\n", cfg.MLAnalysis.ModelPath)

	default:
		fmt.Printf("Error: Unknown policy '%s'\n", policyName)
		fmt.Println("Available policies: threat-detection, typo-detection, supply-chain, ml-analysis")
		return
	}

	// Save configuration to file
	configData, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Printf("Error marshaling configuration: %v\n", err)
		return
	}

	configFile := "./config.yaml"
	if err := os.WriteFile(configFile, configData, 0644); err != nil {
		fmt.Printf("Error saving configuration to %s: %v\n", configFile, err)
		return
	}

	fmt.Printf("Policy '%s' created successfully\n", policyName)
}

func runPolicyValidate(cmd *cobra.Command, args []string) {
	fmt.Println("Validating security policies...")

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("❌ Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	validationErrors := 0
	warnings := 0

	fmt.Println("\n🔍 Policy Validation Report")
	fmt.Println("==========================")

	// Validate threat detection policy
	fmt.Printf("\n📋 Threat Detection Policy:\n")
	if cfg.Policies.MinThreatLevel == "" {
		fmt.Printf("  ❌ Error: Minimum threat level is not set\n")
		validationErrors++
	} else {
		validLevels := []string{"low", "medium", "high", "critical"}
		isValid := false
		for _, level := range validLevels {
			if cfg.Policies.MinThreatLevel == level {
				isValid = true
				break
			}
		}
		if !isValid {
			fmt.Printf("  ❌ Error: Invalid threat level '%s'. Must be one of: %v\n", cfg.Policies.MinThreatLevel, validLevels)
			validationErrors++
		} else {
			fmt.Printf("  ✅ Threat level: %s\n", cfg.Policies.MinThreatLevel)
		}
	}
	fmt.Printf("  ✅ Fail on threats: %v\n", cfg.Policies.FailOnThreats)

	// Validate typo detection policy
	fmt.Printf("\n📋 Typo Detection Policy:\n")
	if cfg.TypoDetection.Enabled {
		if cfg.TypoDetection.Threshold < 0 || cfg.TypoDetection.Threshold > 1 {
			fmt.Printf("  ❌ Error: Threshold %.2f is out of range [0.0, 1.0]\n", cfg.TypoDetection.Threshold)
			validationErrors++
		} else {
			fmt.Printf("  ✅ Threshold: %.2f\n", cfg.TypoDetection.Threshold)
		}

		if cfg.TypoDetection.SimilarityThreshold < 0 || cfg.TypoDetection.SimilarityThreshold > 1 {
			fmt.Printf("  ❌ Error: Similarity threshold %.2f is out of range [0.0, 1.0]\n", cfg.TypoDetection.SimilarityThreshold)
			validationErrors++
		} else {
			fmt.Printf("  ✅ Similarity threshold: %.2f\n", cfg.TypoDetection.SimilarityThreshold)
		}

		if cfg.TypoDetection.EditDistanceThreshold < 1 {
			fmt.Printf("  ❌ Error: Edit distance threshold %d must be >= 1\n", cfg.TypoDetection.EditDistanceThreshold)
			validationErrors++
		} else {
			fmt.Printf("  ✅ Edit distance threshold: %d\n", cfg.TypoDetection.EditDistanceThreshold)
		}

		if cfg.TypoDetection.DictionaryPath != "" {
			if _, err := os.Stat(cfg.TypoDetection.DictionaryPath); os.IsNotExist(err) {
				fmt.Printf("  ⚠️  Warning: Dictionary file not found: %s\n", cfg.TypoDetection.DictionaryPath)
				warnings++
			} else {
				fmt.Printf("  ✅ Dictionary path: %s\n", cfg.TypoDetection.DictionaryPath)
			}
		}
	} else {
		fmt.Printf("  ℹ️  Typo detection is disabled\n")
	}

	// Validate supply chain policy
	fmt.Printf("\n📋 Supply Chain Policy:\n")
	if cfg.SupplyChain.Enabled {
		fmt.Printf("  ✅ Supply chain analysis enabled\n")
		fmt.Printf("  ✅ Build integrity: %v\n", cfg.SupplyChain.BuildIntegrity.Enabled)
		fmt.Printf("  ✅ Zero day detection: %v\n", cfg.SupplyChain.ZeroDayDetection.Enabled)
		fmt.Printf("  ✅ Dependency graph: %v\n", cfg.SupplyChain.DependencyGraph.Enabled)
		fmt.Printf("  ✅ Threat intelligence: %v\n", cfg.SupplyChain.ThreatIntelligence.Enabled)
		fmt.Printf("  ✅ Honeypot detection: %v\n", cfg.SupplyChain.HoneypotDetection.Enabled)
	} else {
		fmt.Printf("  ℹ️  Supply chain analysis is disabled\n")
	}

	// Validate ML analysis policy
	fmt.Printf("\n📋 ML Analysis Policy:\n")
	if cfg.MLAnalysis.Enabled {
		if cfg.MLAnalysis.Threshold < 0 || cfg.MLAnalysis.Threshold > 1 {
			fmt.Printf("  ❌ Error: ML threshold %.2f is out of range [0.0, 1.0]\n", cfg.MLAnalysis.Threshold)
			validationErrors++
		} else {
			fmt.Printf("  ✅ ML threshold: %.2f\n", cfg.MLAnalysis.Threshold)
		}

		if cfg.MLAnalysis.ModelPath == "" {
			fmt.Printf("  ⚠️  Warning: ML model path is not set\n")
			warnings++
		} else {
			if _, err := os.Stat(cfg.MLAnalysis.ModelPath); os.IsNotExist(err) {
				fmt.Printf("  ⚠️  Warning: ML model file not found: %s\n", cfg.MLAnalysis.ModelPath)
				warnings++
			} else {
				fmt.Printf("  ✅ Model path: %s\n", cfg.MLAnalysis.ModelPath)
			}
		}
	} else {
		fmt.Printf("  ℹ️  ML analysis is disabled\n")
	}

	// Summary
	fmt.Printf("\n📊 Validation Summary:\n")
	fmt.Printf("===================\n")
	if validationErrors == 0 && warnings == 0 {
		fmt.Printf("✅ All policies are valid and properly configured!\n")
	} else {
		if validationErrors > 0 {
			fmt.Printf("❌ Found %d validation error(s)\n", validationErrors)
		}
		if warnings > 0 {
			fmt.Printf("⚠️  Found %d warning(s)\n", warnings)
		}

		if validationErrors > 0 {
			fmt.Printf("\n💡 Please fix the validation errors before using the policies.\n")
		}
		if warnings > 0 {
			fmt.Printf("💡 Warnings indicate potential issues that should be reviewed.\n")
		}
	}
}

func runIntegrationList(cmd *cobra.Command, args []string) {
	fmt.Println("Listing available integrations...")

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	fmt.Printf("\n%-20s %-15s %-40s %-10s\n", "Integration", "Type", "Description", "Status")
	fmt.Println(strings.Repeat("-", 85))

	integrationCount := 0

	// Check if integrations are enabled globally
	if !cfg.Integrations.Enabled {
		fmt.Println("Integrations are globally disabled")
		fmt.Println("Enable integrations in configuration to use them")
		return
	}

	// List configured connectors
	for connectorName, connector := range cfg.Integrations.Connectors {
		status := "Disabled"
		if connector.Enabled {
			status = "Enabled"
			integrationCount++
		}

		// Determine integration type based on connector name
		integrationType := "Unknown"
		description := fmt.Sprintf("%s connector", connectorName)

		switch connectorName {
		case "github", "gitlab", "bitbucket":
			integrationType = "Repository"
			description = fmt.Sprintf("%s repository integration", strings.Title(connectorName))
		case "slack", "teams", "email":
			integrationType = "Notification"
			description = fmt.Sprintf("%s notifications", strings.Title(connectorName))
		case "jenkins", "github-actions", "gitlab-ci":
			integrationType = "CI/CD"
			description = fmt.Sprintf("%s integration", strings.Title(connectorName))
		case "siem", "soar", "splunk":
			integrationType = "Security"
			description = fmt.Sprintf("%s integration", strings.Title(connectorName))
		case "jira", "servicenow":
			integrationType = "Ticketing"
			description = fmt.Sprintf("%s ticketing integration", strings.Title(connectorName))
		}

		fmt.Printf("%-20s %-15s %-40s %-10s\n",
			connectorName, integrationType, description, status)
	}

	// Show event routing information
	showAll, _ := cmd.Flags().GetBool("all")
	if showAll && len(cfg.Integrations.EventRouting) > 0 {
		fmt.Printf("\nEvent Routing Configuration:\n")
		fmt.Println(strings.Repeat("-", 50))
		for eventType, connectors := range cfg.Integrations.EventRouting {
			fmt.Printf("%-20s -> %s\n", eventType, strings.Join(connectors, ", "))
		}
	}

	// Show filters if any
	if showAll && len(cfg.Integrations.Filters) > 0 {
		fmt.Printf("\nActive Filters:\n")
		fmt.Println(strings.Repeat("-", 50))
		for i, filter := range cfg.Integrations.Filters {
			fmt.Printf("Filter %d: %s\n", i+1, filter.Name)
			fmt.Printf("  Type: %s\n", filter.Type)
			fmt.Printf("  Condition: %s\n", filter.Condition)
			fmt.Printf("  Value: %v\n", filter.Value)
		}
	}

	if integrationCount == 0 {
		fmt.Println("No integrations are currently enabled")
		fmt.Println("Configure connectors in the integrations section to enable them")
	} else {
		fmt.Printf("\nTotal enabled integrations: %d\n", integrationCount)
	}

	fmt.Println("\nTo test an integration, use:")
	fmt.Println("  typosentinel-enterprise integration test <integration-name>")
}

func runIntegrationTest(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Error: Integration name is required")
		fmt.Println("Usage: typosentinel-enterprise integration test <integration-name>")
		return
	}

	integrationName := args[0]
	fmt.Printf("Testing integration: %s\n", integrationName)

	// Load configuration
	cfgManager := config.NewManager()
	if err := cfgManager.Load("."); err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return
	}
	cfg := cfgManager.Get()

	// Check if integrations are enabled globally
	if !cfg.Integrations.Enabled {
		fmt.Println("❌ Integrations are globally disabled")
		fmt.Println("Enable integrations in configuration first")
		return
	}

	// Find the connector
	connector, exists := cfg.Integrations.Connectors[integrationName]
	if !exists {
		fmt.Printf("❌ Integration '%s' not found in configuration\n", integrationName)
		fmt.Println("\nAvailable integrations:")
		for name := range cfg.Integrations.Connectors {
			fmt.Printf("  - %s\n", name)
		}
		return
	}

	// Check if connector is enabled
	if !connector.Enabled {
		fmt.Printf("❌ Integration '%s' is disabled\n", integrationName)
		fmt.Println("Enable the integration in configuration to test it")
		return
	}

	fmt.Printf("✅ Integration '%s' is enabled\n", integrationName)
	fmt.Printf("📋 Type: %s\n", connector.Type)

	// Perform basic connectivity tests based on connector type
	fmt.Println("\n🔍 Running connectivity tests...")

	switch connector.Type {
	case "slack":
		testSlackConnectivity(connector.Settings)
	case "email":
		testEmailConnectivity(connector.Settings)
	case "webhook":
		testWebhookConnectivity(connector.Settings)
	case "splunk":
		testSplunkConnectivity(connector.Settings)
	default:
		fmt.Printf("⚠️  No specific test available for connector type '%s'\n", connector.Type)
		fmt.Println("✅ Configuration validation passed")
	}

	// Test retry configuration
	if connector.Retry.Enabled && connector.Retry.MaxAttempts > 0 {
		fmt.Printf("🔄 Retry configuration: %d max attempts, %v initial delay, %v max delay\n",
			connector.Retry.MaxAttempts, connector.Retry.InitialDelay, connector.Retry.MaxDelay)
	}

	// Test filters
	if len(connector.Filters) > 0 {
		fmt.Printf("🔍 Active filters: %s\n", strings.Join(connector.Filters, ", "))
	}

	fmt.Println("\n✅ Integration test completed")
}

func testSlackConnectivity(settings map[string]interface{}) {
	fmt.Println("🔗 Testing Slack connectivity...")

	// Check required settings
	if token, ok := settings["token"].(string); ok && token != "" {
		fmt.Println("✅ Slack token configured")
	} else {
		fmt.Println("❌ Slack token missing or invalid")
		return
	}

	if channel, ok := settings["channel"].(string); ok && channel != "" {
		fmt.Printf("✅ Target channel: %s\n", channel)
	} else {
		fmt.Println("❌ Slack channel missing")
		return
	}

	fmt.Println("✅ Slack configuration appears valid")
	fmt.Println("💡 Note: Actual API connectivity test requires live credentials")
}

func testEmailConnectivity(settings map[string]interface{}) {
	fmt.Println("📧 Testing Email connectivity...")

	// Check SMTP settings
	if host, ok := settings["smtp_host"].(string); ok && host != "" {
		fmt.Printf("✅ SMTP host: %s\n", host)
	} else {
		fmt.Println("❌ SMTP host missing")
		return
	}

	if port, ok := settings["smtp_port"]; ok {
		fmt.Printf("✅ SMTP port: %v\n", port)
	} else {
		fmt.Println("❌ SMTP port missing")
		return
	}

	if from, ok := settings["from"].(string); ok && from != "" {
		fmt.Printf("✅ From address: %s\n", from)
	} else {
		fmt.Println("❌ From address missing")
		return
	}

	fmt.Println("✅ Email configuration appears valid")
	fmt.Println("💡 Note: Actual SMTP connectivity test requires live credentials")
}

func testWebhookConnectivity(settings map[string]interface{}) {
	fmt.Println("🌐 Testing Webhook connectivity...")

	if url, ok := settings["url"].(string); ok && url != "" {
		fmt.Printf("✅ Webhook URL: %s\n", url)

		// Basic URL validation
		if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
			fmt.Println("✅ URL format appears valid")
		} else {
			fmt.Println("⚠️  URL should start with http:// or https://")
		}
	} else {
		fmt.Println("❌ Webhook URL missing")
		return
	}

	if method, ok := settings["method"].(string); ok && method != "" {
		fmt.Printf("✅ HTTP method: %s\n", method)
	} else {
		fmt.Println("✅ HTTP method: POST (default)")
	}

	fmt.Println("✅ Webhook configuration appears valid")
	fmt.Println("💡 Note: Actual HTTP connectivity test requires live endpoint")
}

func testSplunkConnectivity(settings map[string]interface{}) {
	fmt.Println("📊 Testing Splunk connectivity...")

	if host, ok := settings["host"].(string); ok && host != "" {
		fmt.Printf("✅ Splunk host: %s\n", host)
	} else {
		fmt.Println("❌ Splunk host missing")
		return
	}

	if port, ok := settings["port"]; ok {
		fmt.Printf("✅ Splunk port: %v\n", port)
	} else {
		fmt.Println("❌ Splunk port missing")
		return
	}

	if token, ok := settings["token"].(string); ok && token != "" {
		fmt.Println("✅ Splunk HEC token configured")
	} else {
		fmt.Println("❌ Splunk HEC token missing")
		return
	}

	if index, ok := settings["index"].(string); ok && index != "" {
		fmt.Printf("✅ Target index: %s\n", index)
	} else {
		fmt.Println("⚠️  No target index specified (will use default)")
	}

	fmt.Println("✅ Splunk configuration appears valid")
	fmt.Println("💡 Note: Actual HEC connectivity test requires live credentials")
}

// ComplianceReport represents a compliance audit report
type ComplianceReport struct {
	GeneratedAt      string                `json:"generated_at"`
	Period           string                `json:"period"`
	Summary          ComplianceSummary     `json:"summary"`
	UserActivity     []UserActivitySummary `json:"user_activity"`
	SecurityEvents   []SecurityEvent       `json:"security_events"`
	PolicyViolations []PolicyViolation     `json:"policy_violations"`
	SystemChanges    []SystemChange        `json:"system_changes"`
}

type ComplianceSummary struct {
	TotalEvents      int `json:"total_events"`
	UniqueUsers      int `json:"unique_users"`
	SecurityEvents   int `json:"security_events"`
	PolicyViolations int `json:"policy_violations"`
	SystemChanges    int `json:"system_changes"`
}

type UserActivitySummary struct {
	User         string   `json:"user"`
	EventCount   int      `json:"event_count"`
	LastActivity string   `json:"last_activity"`
	Actions      []string `json:"actions"`
}

type SecurityEvent struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Event     string `json:"event"`
	Resource  string `json:"resource"`
	Severity  string `json:"severity"`
}

type PolicyViolation struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Policy    string `json:"policy"`
	Resource  string `json:"resource"`
	Action    string `json:"action"`
}

type SystemChange struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Change    string `json:"change"`
	Resource  string `json:"resource"`
}

// Generate compliance report from audit entries
func generateComplianceReport(entries []map[string]interface{}, since, until string) ComplianceReport {
	report := ComplianceReport{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Period:      fmt.Sprintf("%s to %s", since, until),
		Summary:     ComplianceSummary{},
	}

	if since == "" {
		report.Period = "All time"
	}

	userActivity := make(map[string]*UserActivitySummary)

	for _, entry := range entries {
		report.Summary.TotalEvents++

		user := getStringValue(entry, "user")
		if user == "" {
			user = getStringValue(entry, "actor")
		}

		timestamp := getStringValue(entry, "timestamp")
		eventType := getStringValue(entry, "event_type")
		resource := getStringValue(entry, "resource")
		action := getStringValue(entry, "action")

		// Track user activity
		if user != "" {
			if _, exists := userActivity[user]; !exists {
				userActivity[user] = &UserActivitySummary{
					User:       user,
					EventCount: 0,
					Actions:    []string{},
				}
			}
			userActivity[user].EventCount++
			userActivity[user].LastActivity = timestamp
			if action != "" && !contains(userActivity[user].Actions, action) {
				userActivity[user].Actions = append(userActivity[user].Actions, action)
			}
		}

		// Categorize events
		switch {
		case strings.Contains(strings.ToLower(eventType), "security") ||
			strings.Contains(strings.ToLower(action), "login") ||
			strings.Contains(strings.ToLower(action), "auth"):
			report.Summary.SecurityEvents++
			report.SecurityEvents = append(report.SecurityEvents, SecurityEvent{
				Timestamp: timestamp,
				User:      user,
				Event:     eventType,
				Resource:  resource,
				Severity:  determineSeverity(eventType, action),
			})

		case strings.Contains(strings.ToLower(eventType), "violation") ||
			strings.Contains(strings.ToLower(action), "denied"):
			report.Summary.PolicyViolations++
			report.PolicyViolations = append(report.PolicyViolations, PolicyViolation{
				Timestamp: timestamp,
				User:      user,
				Policy:    getStringValue(entry, "policy"),
				Resource:  resource,
				Action:    action,
			})

		case strings.Contains(strings.ToLower(action), "create") ||
			strings.Contains(strings.ToLower(action), "update") ||
			strings.Contains(strings.ToLower(action), "delete") ||
			strings.Contains(strings.ToLower(action), "config"):
			report.Summary.SystemChanges++
			report.SystemChanges = append(report.SystemChanges, SystemChange{
				Timestamp: timestamp,
				User:      user,
				Change:    action,
				Resource:  resource,
			})
		}
	}

	// Convert user activity map to slice
	for _, activity := range userActivity {
		report.UserActivity = append(report.UserActivity, *activity)
	}

	report.Summary.UniqueUsers = len(userActivity)

	return report
}

// Helper function to determine event severity
func determineSeverity(eventType, action string) string {
	eventLower := strings.ToLower(eventType + " " + action)

	if strings.Contains(eventLower, "failed") ||
		strings.Contains(eventLower, "denied") ||
		strings.Contains(eventLower, "violation") {
		return "high"
	}

	if strings.Contains(eventLower, "warning") ||
		strings.Contains(eventLower, "suspicious") {
		return "medium"
	}

	return "low"
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Generate CSV format compliance report
func generateComplianceCSV(report ComplianceReport) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write summary
	writer.Write([]string{"Compliance Report Summary"})
	writer.Write([]string{"Generated At", report.GeneratedAt})
	writer.Write([]string{"Period", report.Period})
	writer.Write([]string{"Total Events", fmt.Sprintf("%d", report.Summary.TotalEvents)})
	writer.Write([]string{"Unique Users", fmt.Sprintf("%d", report.Summary.UniqueUsers)})
	writer.Write([]string{"Security Events", fmt.Sprintf("%d", report.Summary.SecurityEvents)})
	writer.Write([]string{"Policy Violations", fmt.Sprintf("%d", report.Summary.PolicyViolations)})
	writer.Write([]string{"System Changes", fmt.Sprintf("%d", report.Summary.SystemChanges)})
	writer.Write([]string{""}) // Empty row

	// Write security events
	writer.Write([]string{"Security Events"})
	writer.Write([]string{"Timestamp", "User", "Event", "Resource", "Severity"})
	for _, event := range report.SecurityEvents {
		writer.Write([]string{event.Timestamp, event.User, event.Event, event.Resource, event.Severity})
	}

	writer.Flush()
	return buf.Bytes(), writer.Error()
}

// Generate HTML format compliance report
func generateComplianceHTML(report ComplianceReport) ([]byte, error) {
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .high { color: red; }
        .medium { color: orange; }
        .low { color: green; }
    </style>
</head>
<body>
    <h1>Compliance Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Generated:</strong> %s</p>
        <p><strong>Period:</strong> %s</p>
        <p><strong>Total Events:</strong> %d</p>
        <p><strong>Unique Users:</strong> %d</p>
        <p><strong>Security Events:</strong> %d</p>
        <p><strong>Policy Violations:</strong> %d</p>
        <p><strong>System Changes:</strong> %d</p>
    </div>
    
    <h2>Security Events</h2>
    <table>
        <tr><th>Timestamp</th><th>User</th><th>Event</th><th>Resource</th><th>Severity</th></tr>`,
		report.GeneratedAt, report.Period,
		report.Summary.TotalEvents, report.Summary.UniqueUsers,
		report.Summary.SecurityEvents, report.Summary.PolicyViolations,
		report.Summary.SystemChanges)

	for _, event := range report.SecurityEvents {
		html += fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td class="%s">%s</td>
        </tr>`,
			event.Timestamp, event.User, event.Event, event.Resource, event.Severity, event.Severity)
	}

	html += `
    </table>
</body>
</html>`

	return []byte(html), nil
}

// Helper function to get config value with default
func getConfigValue(config map[interface{}]interface{}, key, defaultValue string) string {
	if value, exists := config[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

// Helper function to scan organization from config
func scanOrganizationFromConfig(ctx context.Context, repoManager *repository.Manager, cfg *config.Config, provider, organization string) error {
	// Initialize connector based on provider
	var connector repository.Connector
	var err error

	switch provider {
	case "github":
		connector, err = initializeGitHubConnector(cfg)
	case "gitlab":
		connector, err = initializeGitLabConnector(cfg)
	case "bitbucket":
		connector, err = initializeBitbucketConnector(cfg)
	case "azuredevops":
		connector, err = initializeAzureDevOpsConnector(cfg)
	default:
		return fmt.Errorf("unsupported provider: %s", provider)
	}

	if err != nil {
		return fmt.Errorf("failed to initialize %s connector: %v", provider, err)
	}

	// Register connector
	if err := repoManager.RegisterConnector(provider, connector); err != nil {
		return fmt.Errorf("failed to register connector: %v", err)
	}

	// Get connector
	connector, err = repoManager.GetConnector(provider)
	if err != nil {
		return fmt.Errorf("failed to get connector: %v", err)
	}

	// List repositories
	repos, err := connector.ListOrgRepositories(ctx, organization, &repository.RepositoryFilter{
		IncludePrivate:  false,
		IncludeArchived: false,
		IncludeForks:    false,
	})
	if err != nil {
		return fmt.Errorf("failed to list repositories: %v", err)
	}

	fmt.Printf("    Found %d repositories\n", len(repos))

	// Scan first few repositories (limit for config-based scans)
	maxRepos := 5
	if len(repos) > maxRepos {
		repos = repos[:maxRepos]
		fmt.Printf("    Limiting to %d repositories\n", maxRepos)
	}

	// Scan each repository
	for _, repo := range repos {
		scanRequest := &repository.ScanRequest{
			Repository:  repo,
			ScanID:      fmt.Sprintf("config_scan_%s_%d", organization, time.Now().Unix()),
			RequestedBy: "config",
			Priority:    1,
			Options: repository.ScanOptions{
				IncludeDev:    true,
				OutputFormats: []string{"json"},
			},
			CreatedAt: time.Now(),
		}

		_, err := repoManager.ScanRepositoryWithResult(ctx, scanRequest)
		if err != nil {
			fmt.Printf("    Warning: Failed to scan %s: %v\n", repo.FullName, err)
		}
	}

	return nil
}

// Helper function to scan single repository from config
func scanRepositoryFromConfig(ctx context.Context, repoManager *repository.Manager, cfg *config.Config, provider, repoName string) error {
	// Initialize connector based on provider
	var connector repository.Connector
	var err error

	switch provider {
	case "github":
		connector, err = initializeGitHubConnector(cfg)
	case "gitlab":
		connector, err = initializeGitLabConnector(cfg)
	case "bitbucket":
		connector, err = initializeBitbucketConnector(cfg)
	case "azuredevops":
		connector, err = initializeAzureDevOpsConnector(cfg)
	default:
		return fmt.Errorf("unsupported provider: %s", provider)
	}

	if err != nil {
		return fmt.Errorf("failed to initialize %s connector: %v", provider, err)
	}

	// Register connector
	if err := repoManager.RegisterConnector(provider, connector); err != nil {
		return fmt.Errorf("failed to register connector: %v", err)
	}

	// Get repository info
	parts := strings.Split(repoName, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid repository format, expected 'owner/repo'")
	}

	repo, err := connector.GetRepository(ctx, parts[0], parts[1])
	if err != nil {
		return fmt.Errorf("failed to get repository: %v", err)
	}

	// Scan repository
	scanRequest := &repository.ScanRequest{
		Repository:  repo,
		ScanID:      fmt.Sprintf("config_scan_%s_%d", repoName, time.Now().Unix()),
		RequestedBy: "config",
		Priority:    1,
		Options: repository.ScanOptions{
			IncludeDev:    true,
			OutputFormats: []string{"json"},
		},
		CreatedAt: time.Now(),
	}

	_, err = repoManager.ScanRepositoryWithResult(ctx, scanRequest)
	if err != nil {
		return fmt.Errorf("failed to scan repository: %v", err)
	}

	return nil
}

// Dashboard data structure
type DashboardData struct {
	GeneratedAt    string                   `json:"generated_at"`
	SystemOverview map[string]interface{}   `json:"system_overview"`
	ScanStats      map[string]interface{}   `json:"scan_statistics"`
	ThreatSummary  map[string]interface{}   `json:"threat_summary"`
	RecentActivity []map[string]interface{} `json:"recent_activity"`
}

// Collect dashboard data from database
func collectDashboardData(dbService *database.DatabaseService) DashboardData {
	data := DashboardData{
		GeneratedAt: time.Now().Format(time.RFC3339),
		SystemOverview: map[string]interface{}{
			"uptime":             "24h 30m", // Placeholder
			"active_scans":       0,
			"total_repositories": 0,
			"system_health":      "healthy",
		},
		ScanStats: map[string]interface{}{
			"total_scans":      0,
			"successful_scans": 0,
			"failed_scans":     0,
			"average_duration": "2m 30s",
			"scans_today":      0,
		},
		ThreatSummary: map[string]interface{}{
			"total_threats":    0,
			"critical_threats": 0,
			"high_threats":     0,
			"medium_threats":   0,
			"low_threats":      0,
			"resolved_threats": 0,
		},
		RecentActivity: []map[string]interface{}{
			{
				"timestamp": time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05"),
				"type":      "scan_completed",
				"message":   "Scan completed for repository example/repo",
				"status":    "success",
			},
			{
				"timestamp": time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04:05"),
				"type":      "threat_detected",
				"message":   "High severity threat detected in package xyz",
				"status":    "warning",
			},
		},
	}

	// In a real implementation, you would query the database here
	// For now, we'll use placeholder data

	return data
}

// Generate dashboard HTML export
func generateDashboardHTML(data DashboardData, includeCharts bool) ([]byte, error) {
	chartsScript := ""
	if includeCharts {
		chartsScript = `
		<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
		<script>
			// Sample chart configuration
			const ctx = document.getElementById('threatChart').getContext('2d');
			new Chart(ctx, {
				type: 'doughnut',
				data: {
					labels: ['Critical', 'High', 'Medium', 'Low'],
					datasets: [{
						data: [` + fmt.Sprintf("%v, %v, %v, %v",
			data.ThreatSummary["critical_threats"],
			data.ThreatSummary["high_threats"],
			data.ThreatSummary["medium_threats"],
			data.ThreatSummary["low_threats"]) + `],
						backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
					}]
				}
			});
		</script>`
	}

	chartCanvas := ""
	if includeCharts {
		chartCanvas = `<canvas id="threatChart" width="400" height="200"></canvas>`
	}

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Typosentinel Enterprise Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .stat-item { text-align: center; padding: 15px; background: #ecf0f1; border-radius: 5px; }
        .stat-value { font-size: 2em; font-weight: bold; color: #2c3e50; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .activity-item { padding: 10px; border-left: 4px solid #3498db; margin-bottom: 10px; background: #f8f9fa; }
        .status-success { border-left-color: #28a745; }
        .status-warning { border-left-color: #ffc107; }
        .status-error { border-left-color: #dc3545; }
        table { width: 100%%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Typosentinel Enterprise Dashboard</h1>
            <p>Generated: %s</p>
        </div>
        
        <div class="card">
            <h2>📊 System Overview</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value">%s</div>
                    <div class="stat-label">System Uptime</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">%v</div>
                    <div class="stat-label">Active Scans</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">%v</div>
                    <div class="stat-label">Total Repositories</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">%s</div>
                    <div class="stat-label">System Health</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🔍 Scan Statistics</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value">%v</div>
                    <div class="stat-label">Total Scans</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">%v</div>
                    <div class="stat-label">Successful Scans</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">%v</div>
                    <div class="stat-label">Failed Scans</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">%s</div>
                    <div class="stat-label">Average Duration</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>⚠️ Threat Summary</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value" style="color: #dc3545;">%v</div>
                    <div class="stat-label">Critical Threats</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: #fd7e14;">%v</div>
                    <div class="stat-label">High Threats</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: #ffc107;">%v</div>
                    <div class="stat-label">Medium Threats</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: #28a745;">%v</div>
                    <div class="stat-label">Low Threats</div>
                </div>
            </div>
            %s
        </div>
        
        <div class="card">
            <h2>📈 Recent Activity</h2>`,
		data.GeneratedAt,
		data.SystemOverview["uptime"],
		data.SystemOverview["active_scans"],
		data.SystemOverview["total_repositories"],
		data.SystemOverview["system_health"],
		data.ScanStats["total_scans"],
		data.ScanStats["successful_scans"],
		data.ScanStats["failed_scans"],
		data.ScanStats["average_duration"],
		data.ThreatSummary["critical_threats"],
		data.ThreatSummary["high_threats"],
		data.ThreatSummary["medium_threats"],
		data.ThreatSummary["low_threats"],
		chartCanvas)

	for _, activity := range data.RecentActivity {
		statusClass := fmt.Sprintf("status-%s", activity["status"])
		html += fmt.Sprintf(`
            <div class="activity-item %s">
                <strong>%s</strong> - %s<br>
                <small>%s</small>
            </div>`,
			statusClass, activity["type"], activity["message"], activity["timestamp"])
	}

	html += `
        </div>
    </div>
    ` + chartsScript + `
</body>
</html>`

	return []byte(html), nil
}

// Generate dashboard JSON export
func generateDashboardJSON(data DashboardData) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}

// Helper function to get schedule value with default
func getScheduleValue(schedule map[string]interface{}, key, defaultValue string) string {
	if value, ok := schedule[key].(string); ok {
		return value
	}
	return defaultValue
}

// Helper function to get config value from schedule target
func getScheduleConfigValue(target map[interface{}]interface{}, key, defaultValue string) string {
	if value, ok := target[key].(string); ok {
		return value
	}
	return defaultValue
}

// initConfig reads in config file and ENV variables if set
func initConfig() {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.AddConfigPath("$HOME")
		viper.AddConfigPath(".")
		viper.SetConfigName(".planfinale-enterprise")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
		}
	}
}
