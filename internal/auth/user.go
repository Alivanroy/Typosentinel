package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// UserService handles user management operations
type UserService struct {
	db   *sql.DB
	auth *AuthService
}

// NewUserService creates a new user service
func NewUserService(db *sql.DB, auth *AuthService) *UserService {
	return &UserService{
		db:   db,
		auth: auth,
	}
}

// User represents a user in the system
type User struct {
	ID             uuid.UUID  `json:"id"`
	Username       string     `json:"username"`
	Email          string     `json:"email"`
	FullName       string     `json:"full_name"`
	Role           string     `json:"role"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	IsActive       bool       `json:"is_active"`
	LastLogin      *time.Time `json:"last_login,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Username       string    `json:"username" binding:"required,min=3,max=50"`
	Email          string    `json:"email" binding:"required,email"`
	Password       string    `json:"password" binding:"required,min=8"`
	FullName       string    `json:"full_name" binding:"required"`
	Role           string    `json:"role" binding:"required,oneof=user analyst admin readonly"`
	OrganizationID uuid.UUID `json:"organization_id" binding:"required"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	FullName *string `json:"full_name,omitempty"`
	Role     *string `json:"role,omitempty" binding:"omitempty,oneof=user analyst admin readonly"`
	IsActive *bool   `json:"is_active,omitempty"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	User   *User      `json:"user"`
	Tokens *TokenPair `json:"tokens"`
}

// CreateUser creates a new user
func (s *UserService) CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
	// Hash password
	passwordHash, err := s.auth.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate user ID
	userID := uuid.New()
	now := time.Now()

	// Insert user into database
	query := `
		INSERT INTO users (id, username, email, password_hash, full_name, role, organization_id, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, username, email, full_name, role, organization_id, is_active, created_at, updated_at
	`

	var user User
	err = s.db.QueryRowContext(ctx, query,
		userID, req.Username, req.Email, passwordHash, req.FullName,
		req.Role, req.OrganizationID, true, now, now,
	).Scan(
		&user.ID, &user.Username, &user.Email, &user.FullName,
		&user.Role, &user.OrganizationID, &user.IsActive,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &user, nil
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(ctx context.Context, userID uuid.UUID) (*User, error) {
	query := `
		SELECT id, username, email, full_name, role, organization_id, is_active, last_login, created_at, updated_at
		FROM users
		WHERE id = $1 AND is_active = true
	`

	var user User
	var lastLogin sql.NullTime

	err := s.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.FullName,
		&user.Role, &user.OrganizationID, &user.IsActive,
		&lastLogin, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (s *UserService) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	query := `
		SELECT id, username, email, full_name, role, organization_id, is_active, last_login, created_at, updated_at
		FROM users
		WHERE username = $1 AND is_active = true
	`

	var user User
	var lastLogin sql.NullTime

	err := s.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.FullName,
		&user.Role, &user.OrganizationID, &user.IsActive,
		&lastLogin, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

// UpdateUser updates a user
func (s *UserService) UpdateUser(ctx context.Context, userID uuid.UUID, req *UpdateUserRequest) (*User, error) {
	// Build dynamic update query
	setClauses := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIndex := 1

	if req.FullName != nil {
		setClauses = append(setClauses, fmt.Sprintf("full_name = $%d", argIndex))
		args = append(args, *req.FullName)
		argIndex++
	}

	if req.Role != nil {
		setClauses = append(setClauses, fmt.Sprintf("role = $%d", argIndex))
		args = append(args, *req.Role)
		argIndex++
	}

	if req.IsActive != nil {
		setClauses = append(setClauses, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *req.IsActive)
		argIndex++
	}

	args = append(args, userID)
	query := fmt.Sprintf(`
		UPDATE users
		SET %s
		WHERE id = $%d
		RETURNING id, username, email, full_name, role, organization_id, is_active, last_login, created_at, updated_at
	`, fmt.Sprintf("%s", setClauses), argIndex)

	var user User
	var lastLogin sql.NullTime

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&user.ID, &user.Username, &user.Email, &user.FullName,
		&user.Role, &user.OrganizationID, &user.IsActive,
		&lastLogin, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}

	return &user, nil
}

// DeleteUser soft deletes a user
func (s *UserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1`

	result, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// ListUsers lists users with pagination
func (s *UserService) ListUsers(ctx context.Context, organizationID uuid.UUID, limit, offset int) ([]*User, int, error) {
	// Get total count
	countQuery := `SELECT COUNT(*) FROM users WHERE organization_id = $1 AND is_active = true`
	var total int
	err := s.db.QueryRowContext(ctx, countQuery, organizationID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get user count: %w", err)
	}

	// Get users
	query := `
		SELECT id, username, email, full_name, role, organization_id, is_active, last_login, created_at, updated_at
		FROM users
		WHERE organization_id = $1 AND is_active = true
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := s.db.QueryContext(ctx, query, organizationID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		var lastLogin sql.NullTime

		err := rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.FullName,
			&user.Role, &user.OrganizationID, &user.IsActive,
			&lastLogin, &user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}

		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}

		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate users: %w", err)
	}

	return users, total, nil
}

// Login authenticates a user and returns tokens
func (s *UserService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	// Get user with password hash
	query := `
		SELECT id, username, email, password_hash, full_name, role, organization_id, is_active
		FROM users
		WHERE username = $1 AND is_active = true
	`

	var user User
	var passwordHash string

	err := s.db.QueryRowContext(ctx, query, req.Username).Scan(
		&user.ID, &user.Username, &user.Email, &passwordHash,
		&user.FullName, &user.Role, &user.OrganizationID, &user.IsActive,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid credentials")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Verify password
	if err := s.auth.VerifyPassword(req.Password, passwordHash); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login
	updateQuery := `UPDATE users SET last_login = NOW() WHERE id = $1`
	_, err = s.db.ExecContext(ctx, updateQuery, user.ID)
	if err != nil {
		// Log error but don't fail login
		fmt.Printf("Failed to update last login: %v\n", err)
	}

	// Generate tokens
	permissions := GetDefaultPermissions(user.Role)
	tokens, err := s.auth.GenerateTokenPair(
		user.ID.String(),
		user.OrganizationID.String(),
		user.Role,
		permissions,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &LoginResponse{
		User:   &user,
		Tokens: tokens,
	}, nil
}

// ChangePassword changes a user's password
func (s *UserService) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	// Get current password hash
	query := `SELECT password_hash FROM users WHERE id = $1 AND is_active = true`
	var currentHash string
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&currentHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Verify current password
	if err := s.auth.VerifyPassword(currentPassword, currentHash); err != nil {
		return fmt.Errorf("invalid current password")
	}

	// Hash new password
	newHash, err := s.auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password
	updateQuery := `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`
	_, err = s.db.ExecContext(ctx, updateQuery, newHash, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}