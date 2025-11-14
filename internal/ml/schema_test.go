package ml

import (
    "testing"
    "time"
)

func TestValidateModelInfo(t *testing.T) {
    mi := &ModelInfo{Name: "m", Version: "1", Type: "t", TrainedAt: time.Now(), FeatureCount: 1}
    r := ValidateModelInfo(mi)
    if !r.Valid { t.Fatalf("invalid: %v", r.Errors) }
}

