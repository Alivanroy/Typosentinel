# Repository Connectors

This package provides connectors for integrating with various repository platforms including GitHub, GitLab, Bitbucket, and Azure DevOps. The connectors enable Typosentinel to discover, scan, and analyze repositories across multiple platforms.

## Supported Platforms

### GitHub
- **Platform**: GitHub.com and GitHub Enterprise
- **Authentication**: Personal Access Token, GitHub App
- **Features**: Repository discovery, organization scanning, search, webhooks, rate limiting
- **API Version**: v3 (REST API)

### GitLab
- **Platform**: GitLab.com and self-hosted GitLab instances
- **Authentication**: Personal Access Token, OAuth2
- **Features**: Project discovery, group scanning, search, webhooks, rate limiting
- **API Version**: v4

### Bitbucket
- **Platform**: Bitbucket Cloud and Bitbucket Server
- **Authentication**: App Password, OAuth2
- **Features**: Repository discovery, workspace scanning, search
- **API Version**: 2.0

### Azure DevOps
- **Platform**: Azure DevOps Services and Azure DevOps Server
- **Authentication**: Personal Access Token, OAuth2
- **Features**: Repository discovery, organization/project scanning, search
- **API Version**: 7.0

## Architecture

### Core Components

1. **Connector Interface**: Defines the standard interface that all platform connectors must implement
2. **Factory**: Creates and manages connector instances for different platforms
3. **Discovery Service**: Orchestrates repository discovery across multiple platforms
4. **Repository Manager**: High-level manager for coordinating multiple connectors

### Key Interfaces

```go
type Connector interface {
    // Platform information
    GetPlatformName() string
    GetPlatformType() string
    GetAPIVersion() string

    // Authentication
    Authenticate(ctx context.Context, config AuthConfig) error
    ValidateAuth(ctx context.Context) error
    RefreshAuth(ctx context.Context) error

    // Repository operations
    ListRepositories(ctx context.Context, owner string, filter *RepositoryFilter) ([]*Repository, error)
    GetRepository(ctx context.Context, owner, name string) (*Repository, error)
    SearchRepositories(ctx context.Context, query string, filter *RepositoryFilter) ([]*Repository, error)
    
    // ... additional methods
}
```

## Usage

### Basic Setup

```go
import (
    "github.com/Alivanroy/Typosentinel/internal/repository"
    "github.com/Alivanroy/Typosentinel/internal/repository/connectors"
)

// Create a connector factory
factory := connectors.NewFactory()

// Configure a platform
config := repository.PlatformConfig{
    BaseURL: "https://api.github.com",
    Auth: repository.AuthConfig{
        Token: "your-github-token",
    },
    Timeout: 30 * time.Second,
}

// Create a GitHub connector
connector, err := factory.CreateConnector("github", config)
if err != nil {
    log.Fatal(err)
}

// Use the connector
repos, err := connector.ListRepositories(ctx, "owner", nil)
if err != nil {
    log.Fatal(err)
}
```

### Discovery Service

```go
// Create a repository manager
manager := repository.NewManager(repository.DefaultManagerConfig())

// Add connectors
manager.AddConnector("github", githubConnector)
manager.AddConnector("gitlab", gitlabConnector)

// Configure discovery
discoveryConfig := repository.DiscoveryConfig{
    Platforms: []repository.PlatformDiscoveryConfig{
        {
            Platform: "github",
            Enabled:  true,
            Organizations: []string{"myorg"},
        },
        {
            Platform: "gitlab",
            Enabled:  true,
            Organizations: []string{"mygroup"},
        },
    },
    Interval: 1 * time.Hour,
    MaxReposPerPlatform: 1000,
    IncludePrivate: false,
    Workers: 4,
}

// Start discovery service
discovery := repository.NewDiscoveryService(manager, discoveryConfig)
err := discovery.Start(ctx)
if err != nil {
    log.Fatal(err)
}

// Discover repositories once
results, err := discovery.DiscoverOnce(ctx)
if err != nil {
    log.Fatal(err)
}
```

## Configuration

### Platform Configuration

Each platform connector requires specific configuration:

```yaml
platforms:
  github:
    base_url: "https://api.github.com"
    auth:
      token: "${GITHUB_TOKEN}"
    timeout: "30s"
    rate_limit:
      requests_per_hour: 5000
  
  gitlab:
    base_url: "https://gitlab.com/api/v4"
    auth:
      token: "${GITLAB_TOKEN}"
    timeout: "30s"
  
  bitbucket:
    base_url: "https://api.bitbucket.org/2.0"
    auth:
      username: "${BITBUCKET_USERNAME}"
      password: "${BITBUCKET_APP_PASSWORD}"
    timeout: "30s"
  
  azuredevops:
    base_url: "https://dev.azure.com"
    auth:
      token: "${AZURE_DEVOPS_TOKEN}"
    timeout: "30s"
```

### Repository Filtering

Connectors support comprehensive filtering options:

```go
filter := &repository.RepositoryFilter{
    Languages:       []string{"Go", "Python", "JavaScript"},
    Topics:          []string{"security", "scanning"},
    IncludePrivate:  false,
    IncludeArchived: false,
    IncludeForks:    false,
    MinStars:        10,
    MaxSize:         100 * 1024 * 1024, // 100MB
    NamePattern:     "api-*",
    ExcludePatterns: []string{"test-*", "demo-*"},
}
```

## Authentication

### GitHub
- **Personal Access Token**: Classic tokens with appropriate scopes
- **GitHub App**: App installation tokens (recommended for organizations)
- **Required Scopes**: `repo`, `read:org`, `read:user`

### GitLab
- **Personal Access Token**: Project or group access tokens
- **OAuth2**: Application tokens
- **Required Scopes**: `read_repository`, `read_user`, `read_api`

### Bitbucket
- **App Password**: Username + app-specific password
- **OAuth2**: Consumer key and secret
- **Required Permissions**: `Repositories:Read`, `Account:Read`

### Azure DevOps
- **Personal Access Token**: Organization-level PAT
- **OAuth2**: Application registration
- **Required Scopes**: `Code (read)`, `Project and team (read)`

## Error Handling

All connectors implement comprehensive error handling:

```go
// Rate limiting
if rateLimitErr := connector.GetRateLimit(ctx); rateLimitErr != nil {
    // Handle rate limit
}

// Authentication errors
if authErr := connector.ValidateAuth(ctx); authErr != nil {
    // Refresh or re-authenticate
}

// Network errors with retry logic
repos, err := connector.ListRepositories(ctx, owner, filter)
if err != nil {
    // Check if retryable
    if isRetryable(err) {
        // Implement backoff and retry
    }
}
```

## Rate Limiting

Each connector respects platform-specific rate limits:

- **GitHub**: 5,000 requests/hour (authenticated)
- **GitLab**: 2,000 requests/minute
- **Bitbucket**: 1,000 requests/hour
- **Azure DevOps**: No published limits, but implements throttling

## Testing

The package includes comprehensive tests:

```bash
# Run all connector tests
go test ./internal/repository/connectors -v

# Run specific platform tests
go test ./internal/repository/connectors -v -run TestGitHub
go test ./internal/repository/connectors -v -run TestGitLab
go test ./internal/repository/connectors -v -run TestBitbucket
go test ./internal/repository/connectors -v -run TestAzureDevOps

# Run discovery tests
go test ./internal/repository -v -run TestDiscovery
```

## Security Considerations

1. **Token Storage**: Never hardcode tokens in source code
2. **Scope Limitation**: Use minimal required scopes for authentication
3. **Token Rotation**: Implement regular token rotation
4. **Rate Limiting**: Respect platform rate limits to avoid blocking
5. **Error Logging**: Avoid logging sensitive authentication data

## Contributing

When adding support for new platforms:

1. Implement the `Connector` interface
2. Add platform-specific data structures
3. Implement authentication methods
4. Add comprehensive tests
5. Update the factory to support the new platform
6. Document configuration requirements

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify token validity and scopes
   - Check base URL configuration
   - Ensure network connectivity

2. **Rate Limiting**
   - Implement exponential backoff
   - Monitor rate limit headers
   - Consider using multiple tokens

3. **Network Timeouts**
   - Increase timeout values
   - Check firewall/proxy settings
   - Verify DNS resolution

### Debug Logging

Enable debug logging for detailed connector behavior:

```go
logger := logrus.New()
logger.SetLevel(logrus.DebugLevel)

// Connectors will use this logger for detailed output
```

## Performance Optimization

1. **Concurrent Requests**: Use worker pools for parallel processing
2. **Caching**: Implement response caching where appropriate
3. **Pagination**: Handle large result sets efficiently
4. **Filtering**: Apply filters server-side when possible
5. **Connection Pooling**: Reuse HTTP connections

## Future Enhancements

- Support for additional platforms (Gitea, SourceForge, etc.)
- Webhook-based real-time updates
- Advanced caching strategies
- Metrics and monitoring integration
- GraphQL API support where available