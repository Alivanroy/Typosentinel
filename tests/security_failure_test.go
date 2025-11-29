package tests

import (
	sec "github.com/Alivanroy/Typosentinel/internal/security"
	"testing"
)

func TestValidateJWTSecretFailurePaths(t *testing.T) {
	v := &sec.SecureConfigValidator{}
	if err := v.ValidateJWTSecret(""); err == nil {
		t.Fatalf("expected error for empty secret")
	}
	if err := v.ValidateJWTSecret("short"); err == nil {
		t.Fatalf("expected error for short secret")
	}
}
