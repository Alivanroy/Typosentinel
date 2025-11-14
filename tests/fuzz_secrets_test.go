package tests

import (
    "testing"
    sec "github.com/Alivanroy/Typosentinel/internal/security"
)

func FuzzValidateJWTSecret(f *testing.F) {
    v := &sec.SecureConfigValidator{}
    seeds := []string{"", "short", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "weak1234567890123456789012345678"}
    for _, s := range seeds { f.Add(s) }
    f.Fuzz(func(t *testing.T, s string) {
        _ = v.ValidateJWTSecret(s)
    })
}

