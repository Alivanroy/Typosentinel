# Contributing to TypoSentinel

## Getting Started
- Install Go 1.23+
- `git clone` and `go build -o typosentinel .`
- Run tests: `go test ./... -v`
- Lint: `golangci-lint run ./...`
- Coverage: `go test ./... -cover -coverprofile=coverage.out && go tool cover -func=coverage.out`
- E2E: `go test -tags e2e ./tests/e2e -v`

## Pull Requests
- Branch from `main`
- Ensure tests pass and lint is clean
- Update docs and changelog when user-facing changes
- Avoid committing secrets; CI runs gitleaks

## Reporting Issues
- Use issue templates for bug reports and feature requests
- Include reproduction steps and environment information

## Code Style
- Follow existing patterns and naming
- Prefer small, focused changes with tests
