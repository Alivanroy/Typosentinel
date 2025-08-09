# User Store Implementation

This document describes the implementation of the user store functionality in the Typosentinel authentication system.

## Overview

The user store provides persistent storage for user authentication data, including user accounts, sessions, roles, and security audit logs. It replaces the previous placeholder implementation with a fully functional PostgreSQL-based solution.

## Components

### 1. Database Schema (`migrations/001_create_users_table.sql`)

The database schema includes the following tables:

- **`users`**: Core user account information
- **`user_sessions`**: Active user sessions
- **`user_roles`**: Available roles in the system
- **`user_role_assignments`**: Role assignments to users
- **`security_audit_log`**: Security event audit trail

### 2. User Repository (`user_repository.go`)

The `UserRepository` interface defines all user data operations:

```go
type UserRepository interface {
    GetUserByUsername(ctx context.Context, username string) (*User, error)
    GetUserByID(ctx context.Context, userID string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)
    CreateUser(ctx context.Context, user *User) error
    UpdateUser(ctx context.Context, user *User) error
    UpdateUserPassword(ctx context.Context, userID, hashedPassword string) error
    UpdateLastLogin(ctx context.Context, userID, clientIP string) error
    // ... and more
}
```

The `PostgreSQLUserRepository` provides the PostgreSQL implementation.

### 3. Authentication Service Integration (`auth_service.go`)

The `AuthService` now includes a `UserRepository` dependency and implements:

- User authentication with database lookup
- Password verification and updates
- Session management
- Security event logging

### 4. Factory Functions (`user_repository_factory.go`)

Provides convenient factory functions to create user repositories:

```go
func NewUserRepository(dbManager *database.DatabaseManager, logger *logger.Logger) (UserRepository, error)
func NewUserRepositoryWithDB(db *sql.DB, logger *logger.Logger) UserRepository
```

## Usage

### 1. Database Setup

First, ensure your database migrations are applied:

```go
// Initialize database manager
dbManager, err := database.NewDatabaseManager(dbConfig, logger)
if err != nil {
    log.Fatal("Failed to initialize database:", err)
}

// Apply migrations (this should be done automatically by the schema manager)
```

### 2. Initialize Authentication Service

```go
// Create user repository
userRepository, err := security.NewUserRepository(dbManager, logger)
if err != nil {
    log.Fatal("Failed to create user repository:", err)
}

// Create authentication service
authService := security.NewAuthService(config, logger, rbacEngine, userRepository)
```

### 3. Using Security Manager

For a complete setup, use the security manager:

```go
// Initialize security manager with user repository
securityManager, err := security.NewSecurityManagerWithUserRepository(logger, rbacEngine, userRepository)
if err != nil {
    log.Fatal("Failed to initialize security manager:", err)
}

// Use the authentication service
authService := securityManager.GetAuthService()
```

### 4. Example Authentication

```go
ctx := context.Background()
authReq := &security.AuthRequest{
    Username: "testuser",
    Password: "testpassword",
}

response, err := authService.Authenticate(ctx, authReq, "127.0.0.1", "test-agent")
if err != nil {
    log.Printf("Authentication failed: %v", err)
} else {
    log.Printf("Authentication successful: %+v", response)
}
```

## User Management

### Creating Users

```go
user := &security.User{
    Username:     "newuser",
    Email:        "user@example.com",
    PasswordHash: hashedPassword, // Use bcrypt or argon2
    IsActive:     true,
    IsVerified:   false,
    Roles:        []string{"user"},
}

err := userRepository.CreateUser(ctx, user)
```

### Password Management

```go
// Change password
err := authService.ChangePassword(ctx, userID, &security.PasswordChangeRequest{
    CurrentPassword: "oldpassword",
    NewPassword:     "newpassword",
    ConfirmPassword: "newpassword",
})
```

### Role Management

```go
// Assign role
err := userRepository.AssignRole(ctx, userID, "admin", assignedByUserID)

// Remove role
err := userRepository.RemoveRole(ctx, userID, "admin")

// Get user roles
roles, err := userRepository.GetUserRoles(ctx, userID)
```

## Security Features

### Password Security

- Bcrypt and Argon2 password hashing
- Password history tracking (prevents reuse)
- Password expiration policies
- Strong password requirements

### Account Security

- Failed login attempt tracking
- Account locking after multiple failures
- Session management and cleanup
- Multi-factor authentication support

### Audit Logging

All security events are logged to the `security_audit_log` table:

```go
event := &security.AuditEvent{
    UserID:    &userID,
    EventType: "login_success",
    EventData: map[string]interface{}{
        "method": "password",
    },
    IPAddress: clientIP,
    UserAgent: userAgent,
    Success:   true,
}

err := userRepository.LogSecurityEvent(ctx, event)
```

## Configuration

The user store integrates with the existing security configuration:

```go
config := &security.SecurityConfig{
    Authentication: security.AuthenticationConfig{
        PasswordMinLength:      8,
        RequireUppercase:       true,
        RequireLowercase:       true,
        RequireNumbers:         true,
        RequireSymbols:         true,
        PasswordMaxAge:         90 * 24 * time.Hour,
        PasswordHistoryCount:   5,
    },
}
```

## Migration from Placeholder Implementation

The previous placeholder implementation has been replaced with:

1. **Database-backed user storage** instead of in-memory maps
2. **Persistent sessions** stored in the database
3. **Comprehensive audit logging** for all security events
4. **Role-based access control** with database persistence
5. **Enhanced security features** like account locking and password policies

## Error Handling

The implementation includes comprehensive error handling:

- Database connection errors
- User not found scenarios
- Invalid credentials
- Account lockout conditions
- Password policy violations

## Performance Considerations

- Database indexes on frequently queried fields
- Connection pooling through the database manager
- Efficient JSON handling for array fields
- Prepared statements for security

## Testing

The implementation can be tested with:

1. Unit tests for individual repository methods
2. Integration tests with a test database
3. Authentication flow tests
4. Security policy enforcement tests

## Future Enhancements

Potential future improvements:

1. Redis caching for frequently accessed user data
2. Database sharding for large user bases
3. Advanced audit log analysis
4. Integration with external identity providers
5. Enhanced MFA options (TOTP, WebAuthn)