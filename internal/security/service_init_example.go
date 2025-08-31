package security

import (
	"fmt"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// InitializeAuthService initializes the authentication service with all dependencies
func InitializeAuthService(
	config *SecurityConfig,
	logger *logger.Logger,
	rbacEngine *auth.RBACEngine,
	dbManager *database.DatabaseManager,
) (*AuthService, error) {
	// Create user repository
	userRepository, err := NewUserRepository(dbManager, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create user repository: %w", err)
	}

	// Create token store
	tokenStore := NewDatabaseTokenStore(dbManager.GetDB(), logger)

	// Create authentication service
	authService := NewAuthService(config, logger, rbacEngine, userRepository, tokenStore)

	return authService, nil
}

// Example of how to use the authentication service
/*
func main() {
	// Initialize logger
	logger := logger.New()

	// Initialize database
	dbConfig := &database.InitConfig{
		Host:     "localhost",
		Port:     5432,
		Database: "typosentinel",
		Username: "postgres",
		Password: "password",
		SSLMode:  "disable",
	}

	dbManager, err := database.NewDatabaseManager(dbConfig, logger)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer dbManager.Close()

	// Initialize RBAC engine
	rbacEngine := auth.NewRBACEngine()

	// Initialize security config
	config := &SecurityConfig{
		Authentication: AuthenticationConfig{
			PasswordMinLength:      8,
			RequireUppercase:       true,
			RequireLowercase:       true,
			RequireNumbers:         true,
			RequireSymbols:         true,
			PasswordMaxAge:         90 * 24 * time.Hour,
			PasswordHistoryCount:   5,
		},
	}

	// Initialize authentication service
	authService, err := InitializeAuthService(config, logger, rbacEngine, dbManager)
	if err != nil {
		log.Fatal("Failed to initialize auth service:", err)
	}

	// Now you can use the authentication service
	ctx := context.Background()
	authReq := &AuthRequest{
		Username: "testuser",
		Password: "testpassword",
	}

	response, err := authService.Authenticate(ctx, authReq, "127.0.0.1", "test-agent")
	if err != nil {
		log.Printf("Authentication failed: %v", err)
	} else {
		log.Printf("Authentication successful: %+v", response)
	}
}
*/
