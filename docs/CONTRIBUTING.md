# Contributing to TypoSentinel

We welcome contributions to TypoSentinel! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Documentation](#documentation)
- [Additional Resources](#additional-resources)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Set up the development environment
4. Create a new branch for your feature or bug fix
5. Make your changes
6. Test your changes
7. Submit a pull request

## How to Contribute

### Types of Contributions

- **Bug Reports**: Help us identify and fix bugs
- **Feature Requests**: Suggest new features or improvements
- **Code Contributions**: Submit bug fixes, new features, or improvements
- **Documentation**: Improve or add documentation
- **Testing**: Add or improve test coverage

### Before You Start

- Check existing issues and pull requests to avoid duplicates
- For major changes, please open an issue first to discuss the proposed changes
- Make sure your contribution aligns with the project's goals

## Development Setup

### Prerequisites

- Go 1.23 or later
- Git
- Make (optional, for using Makefile commands)

### Setup Instructions

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Typosentinel.git
cd Typosentinel

# Install dependencies
go mod download

# Build the project
go build -o typosentinel

# Run tests
go test ./...
```

## Coding Standards

### Go Code Style

- Follow the official Go formatting guidelines (`gofmt`)
- Use meaningful variable and function names
- Add comments for exported functions and complex logic
- Keep functions small and focused
- Handle errors appropriately

### Code Organization

- Place new features in appropriate packages
- Follow the existing project structure
- Keep related functionality together
- Separate concerns appropriately

### Documentation

- Document all exported functions and types
- Update README.md if your changes affect usage
- Add inline comments for complex algorithms
- Update API documentation when applicable

## Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test
go test ./internal/detector
```

### Writing Tests

- Write unit tests for new functionality
- Ensure good test coverage (aim for >80%)
- Use table-driven tests where appropriate
- Mock external dependencies
- Test both success and error cases

### Integration Tests

- Add integration tests for new features
- Test with real package repositories when possible
- Ensure tests are deterministic and can run offline

## Pull Request Process

### Before Submitting

1. **Update your branch**: Rebase against the latest main branch
2. **Run tests**: Ensure all tests pass
3. **Check formatting**: Run `gofmt` and `go vet`
4. **Update documentation**: Update relevant documentation
5. **Add tests**: Include tests for new functionality

### Pull Request Guidelines

1. **Clear title**: Use a descriptive title
2. **Detailed description**: Explain what changes you made and why
3. **Link issues**: Reference any related issues
4. **Small changes**: Keep PRs focused and reasonably sized
5. **Commit messages**: Use clear, descriptive commit messages

### Review Process

- All PRs require at least one review
- Address reviewer feedback promptly
- Be open to suggestions and improvements
- Maintain a respectful and collaborative tone

## Issue Reporting

### Bug Reports

When reporting bugs, please include:

- **Clear title**: Summarize the issue
- **Description**: Detailed description of the bug
- **Steps to reproduce**: Clear steps to reproduce the issue
- **Expected behavior**: What you expected to happen
- **Actual behavior**: What actually happened
- **Environment**: OS, Go version, TypoSentinel version
- **Logs**: Relevant log output or error messages

### Feature Requests

When requesting features, please include:

- **Clear title**: Summarize the feature
- **Use case**: Explain why this feature would be useful
- **Description**: Detailed description of the proposed feature
- **Alternatives**: Any alternative solutions you've considered

## Development Guidelines

### Branch Naming

- `feature/description` - for new features
- `bugfix/description` - for bug fixes
- `docs/description` - for documentation updates
- `refactor/description` - for code refactoring

### Commit Messages

Use the conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat(detector): add homoglyph detection algorithm

Implement Unicode homoglyph detection to identify visually similar
characters that could be used in typosquatting attacks.

Closes #123
```

### Performance Considerations

- Profile code for performance-critical paths
- Avoid unnecessary allocations
- Use appropriate data structures
- Consider memory usage for large datasets
- Benchmark performance improvements

## Security

If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md) and report it privately.

## Documentation

When contributing, please ensure documentation is updated appropriately:

- **API Changes**: Update [API Documentation](docs/API_DOCUMENTATION.md)
- **User-facing Changes**: Update [User Guide](docs/USER_GUIDE.md)
- **Configuration Changes**: Update configuration examples
- **New Features**: Add to [Project Documentation](PROJECT_DOCUMENTATION.md)
- **Security Changes**: Review [Security Policy](SECURITY.md)

### Generating API Reference

To generate the API reference documentation:

```bash
make docs
```

This will create `docs/API_REFERENCE.md` with the latest API documentation.

## Additional Resources

### Project Documentation

- [README.md](README.md) - Project overview and quick start
- [User Guide](docs/USER_GUIDE.md) - Comprehensive usage guide
- [API Documentation](docs/API_DOCUMENTATION.md) - REST API reference
- [Debug Logging Guide](docs/DEBUG_LOGGING.md) - Debugging and logging
- [Plugin Development Guide](docs/plugin_development_guide.md) - Creating plugins
- [Strategic Implementation Plan](docs/strategic_implementation_plan.md) - Project roadmap
- [Roadmap](ROADMAP.md) - Development roadmap and future plans
- [Production Deployment Guide](PRODUCTION_DEPLOYMENT.md) - Deployment instructions
- [Pre-deployment Checklist](PRE_DEPLOYMENT_CHECKLIST.md) - Deployment validation
- [Project Structure](PROJECT_STRUCTURE.md) - Codebase organization
- [Security Policy](SECURITY.md) - Security guidelines and reporting
- [Code of Conduct](CODE_OF_CONDUCT.md) - Community guidelines
- [Changelog](CHANGELOG.md) - Version history and changes

### Development Resources

- [Optimization Guide](internal/optimization/README.md) - Performance optimization
- [Logger Documentation](pkg/logger/README.md) - Logging utilities
- [Plugin Examples](examples/plugins/) - Plugin development examples

## Questions?

If you have questions about contributing, please:

1. Check the existing documentation listed above
2. Search existing issues
3. Open a new issue with the "question" label
4. Join our community discussions

## Recognition

Contributors will be recognized in our [CHANGELOG.md](CHANGELOG.md) and may be added to a contributors list.

Thank you for contributing to TypoSentinel!