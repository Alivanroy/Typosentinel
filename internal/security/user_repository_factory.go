package security

import (
	"database/sql"
	"fmt"

	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// NewUserRepository creates a new user repository with the given database connection
func NewUserRepository(dbManager *database.DatabaseManager, logger *logger.Logger) (UserRepository, error) {
	if dbManager == nil {
		return nil, fmt.Errorf("database manager cannot be nil")
	}

	// Get the database connection
	db := dbManager.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	return &PostgreSQLUserRepository{
		db: db,
	}, nil
}

// NewUserRepositoryWithDB creates a new user repository with a direct database connection
func NewUserRepositoryWithDB(db *sql.DB, logger *logger.Logger) UserRepository {
	return &PostgreSQLUserRepository{
		db: db,
	}
}

// NewUserRepositoryWithService creates a new user repository with a database service
func NewUserRepositoryWithService(dbService interface{}, logger *logger.Logger) (UserRepository, error) {
	// Check if the service has a GetDB method
	type DBProvider interface {
		GetDB() *sql.DB
	}

	if provider, ok := dbService.(DBProvider); ok {
		db := provider.GetDB()
		if db == nil {
			return nil, fmt.Errorf("database connection is nil")
		}
		return &PostgreSQLUserRepository{
			db: db,
		}, nil
	}

	return nil, fmt.Errorf("database service does not provide GetDB method")
}
