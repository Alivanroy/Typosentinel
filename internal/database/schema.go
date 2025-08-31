package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// SchemaManager handles database schema migrations and initialization
type SchemaManager struct {
	db     *sql.DB
	logger *logger.Logger
}

// Migration represents a database migration
type Migration struct {
	Version   int
	Name      string
	Filename  string
	SQL       string
	AppliedAt *time.Time
	Checksum  string
}

// NewSchemaManager creates a new schema manager
func NewSchemaManager(db *sql.DB, logger *logger.Logger) *SchemaManager {
	return &SchemaManager{
		db:     db,
		logger: logger,
	}
}

// Initialize sets up the database schema and runs migrations
func (sm *SchemaManager) Initialize(ctx context.Context) error {
	// Create migrations table if it doesn't exist
	if err := sm.createMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get available migrations
	migrations, err := sm.getAvailableMigrations()
	if err != nil {
		return fmt.Errorf("failed to get available migrations: %w", err)
	}

	// Get applied migrations
	appliedMigrations, err := sm.getAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Apply pending migrations
	if err := sm.applyPendingMigrations(ctx, migrations, appliedMigrations); err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	sm.logger.Info("Database schema initialization completed")
	return nil
}

// createMigrationsTable creates the schema_migrations table
func (sm *SchemaManager) createMigrationsTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			filename VARCHAR(255) NOT NULL,
			checksum VARCHAR(64) NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_schema_migrations_applied_at ON schema_migrations(applied_at);
	`

	_, err := sm.db.ExecContext(ctx, query)
	return err
}

// getAvailableMigrations reads all migration files from the embedded filesystem
func (sm *SchemaManager) getAvailableMigrations() ([]Migration, error) {
	var migrations []Migration

	err := fs.WalkDir(migrationFiles, "migrations", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}

		filename := filepath.Base(path)
		version, name, err := sm.parseMigrationFilename(filename)
		if err != nil {
			return fmt.Errorf("failed to parse migration filename %s: %w", filename, err)
		}

		content, err := migrationFiles.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", path, err)
		}

		migrations = append(migrations, Migration{
			Version:  version,
			Name:     name,
			Filename: filename,
			SQL:      string(content),
			Checksum: sm.calculateChecksum(content),
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// getAppliedMigrations retrieves migrations that have already been applied
func (sm *SchemaManager) getAppliedMigrations(ctx context.Context) (map[int]Migration, error) {
	applied := make(map[int]Migration)

	query := `
		SELECT version, name, filename, checksum, applied_at
		FROM schema_migrations
		ORDER BY version
	`

	rows, err := sm.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var migration Migration
		var appliedAt time.Time

		err := rows.Scan(
			&migration.Version,
			&migration.Name,
			&migration.Filename,
			&migration.Checksum,
			&appliedAt,
		)
		if err != nil {
			return nil, err
		}

		migration.AppliedAt = &appliedAt
		applied[migration.Version] = migration
	}

	return applied, rows.Err()
}

// applyPendingMigrations applies migrations that haven't been applied yet
func (sm *SchemaManager) applyPendingMigrations(ctx context.Context, available []Migration, applied map[int]Migration) error {
	for _, migration := range available {
		appliedMigration, exists := applied[migration.Version]

		if exists {
			// Verify checksum
			if appliedMigration.Checksum != migration.Checksum {
				return fmt.Errorf("migration %d checksum mismatch: expected %s, got %s",
					migration.Version, appliedMigration.Checksum, migration.Checksum)
			}
			sm.logger.Debug(fmt.Sprintf("Migration %d already applied, skipping", migration.Version))
			continue
		}

		// Apply the migration
		if err := sm.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}

		sm.logger.Info(fmt.Sprintf("Applied migration %d: %s", migration.Version, migration.Name))
	}

	return nil
}

// applyMigration applies a single migration
func (sm *SchemaManager) applyMigration(ctx context.Context, migration Migration) error {
	tx, err := sm.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Execute the migration SQL
	_, err = tx.ExecContext(ctx, migration.SQL)
	if err != nil {
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	// Record the migration as applied
	query := `
		INSERT INTO schema_migrations (version, name, filename, checksum, applied_at)
		VALUES ($1, $2, $3, $4, NOW())
	`
	_, err = tx.ExecContext(ctx, query, migration.Version, migration.Name, migration.Filename, migration.Checksum)
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	return tx.Commit()
}

// parseMigrationFilename parses a migration filename to extract version and name
// Expected format: 001_create_table_name.sql
func (sm *SchemaManager) parseMigrationFilename(filename string) (int, string, error) {
	name := strings.TrimSuffix(filename, ".sql")
	parts := strings.SplitN(name, "_", 2)

	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid migration filename format: %s", filename)
	}

	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("invalid version number in filename: %s", filename)
	}

	return version, parts[1], nil
}

// calculateChecksum calculates a simple checksum for migration content
func (sm *SchemaManager) calculateChecksum(content []byte) string {
	// Simple hash for now - in production, consider using SHA-256
	hash := 0
	for _, b := range content {
		hash = hash*31 + int(b)
	}
	return fmt.Sprintf("%x", hash)
}

// GetMigrationStatus returns the status of all migrations
func (sm *SchemaManager) GetMigrationStatus(ctx context.Context) ([]Migration, error) {
	available, err := sm.getAvailableMigrations()
	if err != nil {
		return nil, err
	}

	applied, err := sm.getAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	for i := range available {
		if appliedMigration, exists := applied[available[i].Version]; exists {
			available[i].AppliedAt = appliedMigration.AppliedAt
		}
	}

	return available, nil
}

// ValidateSchema validates that the current database schema matches expectations
func (sm *SchemaManager) ValidateSchema(ctx context.Context) error {
	// Check that all expected tables exist
	expectedTables := []string{
		"schema_migrations",
		"repositories",
		"organizations",
		"scan_results",
		"scan_findings",
		"scan_jobs",
		"repository_dependencies",
	}

	for _, table := range expectedTables {
		exists, err := sm.tableExists(ctx, table)
		if err != nil {
			return fmt.Errorf("failed to check if table %s exists: %w", table, err)
		}
		if !exists {
			return fmt.Errorf("required table %s does not exist", table)
		}
	}

	sm.logger.Info("Database schema validation completed successfully")
	return nil
}

// tableExists checks if a table exists in the database
func (sm *SchemaManager) tableExists(ctx context.Context, tableName string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables 
			WHERE table_schema = 'public' AND table_name = $1
		)
	`

	var exists bool
	err := sm.db.QueryRowContext(ctx, query, tableName).Scan(&exists)
	return exists, err
}
