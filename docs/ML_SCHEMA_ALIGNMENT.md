# ML Schema Alignment

- Extended `ModelInfo` with `development_warning` for compatibility
- Added validation functions to ensure required fields and sane defaults
- Transformation utilities can be layered to standardize feature inputs

## Validation
- `ValidateModelInfo` checks required fields and timestamps
- `EnsureModelCompatibility` returns error if invalid

