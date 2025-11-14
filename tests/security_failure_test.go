package tests

import (
    "testing"
    sec "github.com/Alivanroy/Typosentinel/internal/security"
)

func TestValidateJWTSecretFailurePaths(t *testing.T) {
    v := &sec.SecureConfigValidator{}
    if err := v.ValidateJWTSecret(""); err == nil { t.Fatalf("expected error for empty secret") }
    if err := v.ValidateJWTSecret("short"); err == nil { t.Fatalf("expected error for short secret") }
}

