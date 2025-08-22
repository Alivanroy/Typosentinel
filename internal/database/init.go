package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	_ "github.com/lib/pq"
)

// InitConfig holds database initialization configuration
type InitConfig struct {
	Host            string        `yaml:"host" env:"DB_HOST" default:"localhost"`
	Port            int           `yaml:"port" env:"DB_PORT" default:"5432"`
	Database        string        `yaml:"database" env:"DB_NAME" default:"typosentinel"`
	Username        string        `yaml:"username" env:"DB_USER" default:"postgres"`
	Password        string        `yaml:"password" env:"DB_PASSWORD" default:""`
	SSLMode         string        `yaml:"ssl_mode" env:"DB_SSL_MODE" default:"disable"`
	MaxOpenConns    int           `yaml:"max_open_conns" env:"DB_MAX_OPEN_CONNS" default:"25"`
	MaxIdleConns    int           `yaml:"max_idle_conns" env:"DB_MAX_IDLE_CONNS" default:"5"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" env:"DB_CONN_MAX_LIFETIME" default:"1h"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time" env:"DB_CONN_MAX_IDLE_TIME" default:"30m"`
}

// DatabaseManager manages database connections and initialization
type DatabaseManager struct {
	db            *sql.DB
	config        InitConfig
	schemaManager *SchemaManager
	service       *DatabaseService
	logger        *logger.Logger
}

// NewDatabaseManager creates a new database manager
func NewDatabaseManager(config InitConfig, logger *logger.Logger) *DatabaseManager {
	return &DatabaseManager{
		config: config,
		logger: logger,
	}
}

// Initialize initializes the database connection and runs migrations
func (dm *DatabaseManager) Initialize(ctx context.Context) error {
	// Connect to database
	if err := dm.connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Initialize schema manager
	dm.schemaManager = NewSchemaManager(dm.db, dm.logger)

	// Run migrations
	if err := dm.schemaManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize database schema: %w", err)
	}

	// Initialize database service
	dbConfig := &config.DatabaseConfig{
		Type:            "postgres",
		Host:            dm.config.Host,
		Port:            dm.config.Port,
		Username:        dm.config.Username,
		Password:        dm.config.Password,
		Database:        dm.config.Database,
		SSLMode:         dm.config.SSLMode,
		MaxOpenConns:    dm.config.MaxOpenConns,
		MaxIdleConns:    dm.config.MaxIdleConns,
		ConnMaxLifetime: dm.config.ConnMaxLifetime,
		MigrationsPath:  "./migrations",
	}
	var err error
	dm.service, err = NewDatabaseService(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize database service: %w", err)
	}

	dm.logger.Info("Database initialized successfully")
	return nil
}

// connect establishes a connection to the database
func (dm *DatabaseManager) connect(ctx context.Context) error {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		dm.config.Host,
		dm.config.Port,
		dm.config.Username,
		dm.config.Password,
		dm.config.Database,
		dm.config.SSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(dm.config.MaxOpenConns)
	db.SetMaxIdleConns(dm.config.MaxIdleConns)
	db.SetConnMaxLifetime(dm.config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(dm.config.ConnMaxIdleTime)

	// Test the connection
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	dm.db = db
	dm.logger.Info("Connected to database")
	return nil
}

// Close closes the database connection
func (dm *DatabaseManager) Close() error {
	if dm.db != nil {
		return dm.db.Close()
	}
	return nil
}

// GetDB returns the database connection
func (dm *DatabaseManager) GetDB() *sql.DB {
	return dm.db
}

// GetService returns the database service
func (dm *DatabaseManager) GetService() *DatabaseService {
	return dm.service
}

// GetSchemaManager returns the schema manager
func (dm *DatabaseManager) GetSchemaManager() *SchemaManager {
	return dm.schemaManager
}

// HealthCheck performs a health check on the database
func (dm *DatabaseManager) HealthCheck(ctx context.Context) error {
	if dm.db == nil {
		return fmt.Errorf("database not initialized")
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return dm.db.PingContext(ctx)
}

// GetMigrationStatus returns the current migration status
func (dm *DatabaseManager) GetMigrationStatus(ctx context.Context) ([]Migration, error) {
	if dm.schemaManager == nil {
		return nil, fmt.Errorf("schema manager not initialized")
	}
	return dm.schemaManager.GetMigrationStatus(ctx)
}

// ValidateSchema validates the database schema
func (dm *DatabaseManager) ValidateSchema(ctx context.Context) error {
	if dm.schemaManager == nil {
		return fmt.Errorf("schema manager not initialized")
	}
	return dm.schemaManager.ValidateSchema(ctx)
}