# Task List

- [x] [Refactor Detector] Breakdown `enhanced_typosquatting.go`
    - [x] Create `internal/detector/tables.go` (keyboards, substitutions)
    - [x] Create `internal/detector/keyboard.go` (keyboard layout logic)
    - [x] Create `internal/detector/visual.go` (visual similarity logic)
    - [x] Create `internal/detector/phonetic.go` (phonetic logic)
    - [x] Update `internal/detector/enhanced_typosquatting.go` to use new files
- [x] [Improve Parsing] Use `golang.org/x/mod`
    - [x] Update `internal/analyzer/analyzer.go` to use `modfile`
    - [x] Update imports in `internal/analyzer/analyzer.go`
    - [x] Verify parsing on `go.mod`
- [x] [Rename ML] Rename `internal/ml` to `internal/heuristics`
    - [x] Rename directory
    - [x] Update package declarations
    - [x] Update imports in consumer files
