# Implementation Plan - Review Recommendations

I will implement the key recommendations from the project review to improve code quality, maintainability, and correctness.

## User Review Required
> [!IMPORTANT]
> **Renaming `internal/ml` to `internal/heuristics`**: This is a structural change that clarifies the component's purpose. It will require updating imports.
> **Dependency Addition**: Adding `golang.org/x/mod` for robust `go.mod` parsing.

## Proposed Changes

### Refactoring `internal/detector`
The `enhanced_typosquatting.go` file is too large (~1250 lines). I will split it into logical components.

#### [NEW] `internal/detector/similarity/`
Create a new sub-package (or just separate files in `detector`) to house specific similarity algorithms.
- `internal/detector/keyboard.go`: Keyboard layout and proximity logic.
- `internal/detector/visual.go`: Visual similarity and substitution logic.
- `internal/detector/phonetic.go`: Phonetic algorithms.
- `internal/detector/tables.go`: Large data tables (substitution maps, keyboard layouts).

#### [MODIFY] `internal/detector/enhanced_typosquatting.go`
- Remove the extracted logic.
- Delegate to the new files/structs.

### Improve Go Module Parsing
Replace hand-rolled `go.mod` parsing in `internal/analyzer/analyzer.go` with `golang.org/x/mod/modfile`.

#### [MODIFY] `internal/analyzer/analyzer.go`
- Import `golang.org/x/mod/modfile`
- Rewrite `parseGoDependencies` to use the library.

### Rename ML Component
Rename `internal/ml` to `internal/heuristics` to accurately reflect its current state (heuristic scoring vs actual ML).

#### [MOVE] `internal/ml` -> `internal/heuristics`
- Rename directory.
- Update package name in files.
- Update imports in `internal/scanner`, `internal/analyzer`, etc.

## Verification Plan

### Automated Tests
- Run existing tests for `detector` to ensure no regression in detection capabilities.
- Run `go test ./internal/analyzer/...` to verify the new Go parser works correctly.
- Run all tests to ensure the renaming didn't break imports.

### Manual Verification
- Run a scan on a sample Go project (e.g. the project itself) to verify `go.mod` parsing.
