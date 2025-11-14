package tests

import (
    "os"
    "testing"
    "github.com/Alivanroy/Typosentinel/internal/security"
)

func TestProductionFailsWithoutJWTSecret(t *testing.T) {
    os.Setenv("TYPOSENTINEL_ENVIRONMENT", "production")
    os.Unsetenv("TYPOSENTINEL_JWT_SECRET")
    os.Setenv("TYPOSENTINEL_ADMIN_PASSWORD", "StrongPassw0rd!")
    v := security.NewSecureConfigValidator()
    if err := v.ValidateProductionConfig(); err == nil {
        t.Fatalf("expected validation error when JWT secret is empty in production")
    }
}