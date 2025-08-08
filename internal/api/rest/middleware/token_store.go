package middleware

import (
	"fmt"
	"sync"
	"time"
)

// TokenInfo represents information about a token
type TokenInfo struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Scope     []string  `json:"scope"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TokenType string    `json:"token_type"`
	LastUsed  time.Time `json:"last_used"`
}

// InMemoryTokenStore provides an in-memory implementation of TokenStore for testing
type InMemoryTokenStore struct {
	tokens   map[string]*TokenInfo
	revoked  map[string]bool
	mutex    sync.RWMutex
}

// NewInMemoryTokenStore creates a new in-memory token store
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		tokens:  make(map[string]*TokenInfo),
		revoked: make(map[string]bool),
	}
}

// ValidateToken validates a token hash and returns token information
func (s *InMemoryTokenStore) ValidateToken(tokenHash string) (*TokenInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	tokenInfo, exists := s.tokens[tokenHash]
	if !exists {
		return nil, fmt.Errorf("token not found")
	}

	// Check if token is expired
	if time.Now().After(tokenInfo.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	return tokenInfo, nil
}

// IsTokenRevoked checks if a token has been revoked
func (s *InMemoryTokenStore) IsTokenRevoked(tokenHash string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.revoked[tokenHash]
}

// UpdateLastUsed updates the last used timestamp for a token
func (s *InMemoryTokenStore) UpdateLastUsed(tokenHash string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tokenInfo, exists := s.tokens[tokenHash]
	if !exists {
		return fmt.Errorf("token not found")
	}

	tokenInfo.LastUsed = time.Now()
	return nil
}

// AddToken adds a new token to the store (for testing purposes)
func (s *InMemoryTokenStore) AddToken(tokenHash string, tokenInfo *TokenInfo) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.tokens[tokenHash] = tokenInfo
}

// RevokeToken revokes a token
func (s *InMemoryTokenStore) RevokeToken(tokenHash string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.revoked[tokenHash] = true
}

// GetTokenCount returns the number of tokens in the store (for testing)
func (s *InMemoryTokenStore) GetTokenCount() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return len(s.tokens)
}

// Clear removes all tokens from the store (for testing)
func (s *InMemoryTokenStore) Clear() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.tokens = make(map[string]*TokenInfo)
	s.revoked = make(map[string]bool)
}