# Contributing to TypoSentinel

Thank you for your interest in contributing! This guide outlines the process and standards we use to keep the project healthy and maintainable.

## Ways to Contribute
- Bug reports and feature requests via GitHub Issues
- Documentation improvements (README, docs/*.md)
- Tests for uncovered areas (see `COVERAGE_TARGETS.md`)
- Performance and security improvements

## Development Workflow
- Fork and clone the repo
- Create a feature branch from `main`
- Run tests: `go test ./... -v`
- Ensure lint passes: `golangci-lint run`
- Validate secret scan: `gitleaks detect --source . --config-path .gitleaks.toml`
- Submit a PR with a clear description, screenshots/logs where helpful

## Commit and PR Guidelines
- Use descriptive commit messages (Conventional Commits encouraged)
  - `feat: add CycloneDX SBOM formatter`
  - `fix: resolve SVG graph layout duplication`
  - `docs: add Code of Conduct`
- Include tests when adding features or fixing bugs
- Keep PRs focused and small; link related issues

## Coding Standards
- Follow existing code style and patterns
- No secrets in code or logs
- Prefer standard libraries and avoid unnecessary dependencies
- Add package‑level comments where missing

## Testing Requirements
- Unit tests must pass on `main`
- E2E tests (where applicable) pass: `go test -tags=e2e ./tests/e2e -v`
- Realworld tests (optional, nightly): `go test -tags=realworld ./tests/e2e -v`

## Release Process
- Tags use semantic versioning: `vMAJOR.MINOR.PATCH`
- CI builds binaries and attaches artifacts on tagged commits
- Release notes use the template in `.github/RELEASE_TEMPLATE.md`

## Security & Reporting
- See `SECURITY.md`
- Report vulnerabilities privately via GitHub Security Advisory or email `security@alivanroy.dev`

## Code of Conduct
- By participating, you agree to abide by our `CODE_OF_CONDUCT.md`.

