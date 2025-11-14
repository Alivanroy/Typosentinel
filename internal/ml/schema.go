package ml

import (
    "fmt"
    "time"
)

type SchemaValidationResult struct {
    Valid   bool
    Errors  []string
}

func ValidateModelInfo(mi *ModelInfo) SchemaValidationResult {
    var errs []string
    if mi == nil { return SchemaValidationResult{Valid: false, Errors: []string{"nil ModelInfo"}} }
    if mi.Name == "" { errs = append(errs, "name required") }
    if mi.Version == "" { errs = append(errs, "version required") }
    if mi.Type == "" { errs = append(errs, "type required") }
    if mi.FeatureCount < 0 { errs = append(errs, "feature_count invalid") }
    if mi.TrainedAt.IsZero() { mi.TrainedAt = time.Now() }
    return SchemaValidationResult{Valid: len(errs) == 0, Errors: errs}
}

func EnsureModelCompatibility(mi *ModelInfo) error {
    res := ValidateModelInfo(mi)
    if !res.Valid {
        return fmt.Errorf("model info invalid: %v", res.Errors)
    }
    return nil
}

