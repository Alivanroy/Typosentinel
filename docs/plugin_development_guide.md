# Plugin Development Guide

This guide explains how to develop language analyzer plugins for TypoSentinel.

## Overview

TypoSentinel supports a plugin architecture that allows developers to add support for new programming languages and package managers. Plugins are implemented as Go plugins (`.so` files) that implement the `LanguageAnalyzer` interface.

## Plugin Interface

All plugins must implement the `LanguageAnalyzer` interface:

```go
type LanguageAnalyzer interface {
    // GetMetadata returns metadata about the analyzer
    GetMetadata() *AnalyzerMetadata
    
    // CanAnalyze determines if this analyzer can handle the given project
    CanAnalyze(projectInfo *ProjectInfo) bool
    
    // AnalyzeProject analyzes a project and returns dependency information
    AnalyzeProject(ctx *AnalyzerContext) (*AnalysisResult, error)
    
    // ExtractDependencies extracts dependencies from project files
    ExtractDependencies(projectInfo *ProjectInfo) ([]*types.Package, error)
    
    // ValidateProject validates project structure and files
    ValidateProject(projectInfo *ProjectInfo) error
}
```

## Plugin Structure

### 1. Plugin Entry Point

Every plugin must export a `NewAnalyzer` function:

```go
package main

import (
    "typosentinel/internal/scanner"
)

// NewAnalyzer is the plugin entry point
func NewAnalyzer() scanner.LanguageAnalyzer {
    return &MyLanguageAnalyzer{}
}

type MyLanguageAnalyzer struct {
    // Plugin-specific fields
}
```

### 2. Metadata Implementation

```go
func (a *MyLanguageAnalyzer) GetMetadata() *scanner.AnalyzerMetadata {
    return &scanner.AnalyzerMetadata{
        Name:        "my-language",
        Version:     "1.0.0",
        Author:      "Your Name",
        Description: "Analyzer for My Programming Language",
        SupportedExtensions: []string{".mylang", ".ml"},
        ManifestFiles: []string{"mylang.toml", "dependencies.mylang"},
    }
}
```

### 3. Project Detection

```go
func (a *MyLanguageAnalyzer) CanAnalyze(projectInfo *scanner.ProjectInfo) bool {
    // Check if this is a project we can analyze
    switch projectInfo.Type {
    case "mylang":
        return true
    default:
        return false
    }
}
```

### 4. Project Analysis

```go
func (a *MyLanguageAnalyzer) AnalyzeProject(ctx *scanner.AnalyzerContext) (*scanner.AnalysisResult, error) {
    // Implement your analysis logic here
    packages, err := a.ExtractDependencies(ctx.ProjectInfo)
    if err != nil {
        return nil, err
    }
    
    return &scanner.AnalysisResult{
        Packages:     packages,
        ProjectType:  "mylang",
        AnalyzerName: "my-language",
        Metadata:     make(map[string]interface{}),
    }, nil
}
```

### 5. Dependency Extraction

```go
func (a *MyLanguageAnalyzer) ExtractDependencies(projectInfo *scanner.ProjectInfo) ([]*types.Package, error) {
    var packages []*types.Package
    
    // Parse manifest file
    manifestPath := filepath.Join(projectInfo.Path, "mylang.toml")
    data, err := ioutil.ReadFile(manifestPath)
    if err != nil {
        return nil, err
    }
    
    // Parse dependencies (implementation specific)
    deps, err := a.parseManifest(data)
    if err != nil {
        return nil, err
    }
    
    // Convert to Package objects
    for _, dep := range deps {
        pkg := &types.Package{
            Name:     dep.Name,
            Version:  dep.Version,
            Registry: "mylang-registry",
            Type:     "mylang",
        }
        packages = append(packages, pkg)
    }
    
    return packages, nil
}
```

## Building Plugins

### 1. Plugin Project Structure

```
my-language-plugin/
├── main.go              # Plugin entry point
├── analyzer.go          # Main analyzer implementation
├── parser.go           # Language-specific parsing logic
├── go.mod              # Go module file
└── README.md           # Plugin documentation
```

### 2. Go Module Setup

```go
// go.mod
module my-language-plugin

go 1.21

require (
    typosentinel v0.1.0
)
```

### 3. Build Command

```bash
# Build the plugin
go build -buildmode=plugin -o my-language.so .
```

## Plugin Configuration

### 1. Global Configuration

Add plugin configuration to your `.typosentinel.yaml`:

```yaml
plugins:
  enabled: true
  plugin_dir: "./plugins"
  auto_load: true
  load_timeout: 30s
  max_plugins: 50
  
  validation:
    require_signed: false
    validate_metadata: true
    trusted_authors: []
    
  security:
    sandbox: false
    restrict_file_access: true
    allowed_directories: ["/tmp", "/var/tmp"]
    
  plugins:
    - name: "my-language"
      path: "./plugins/my-language.so"
      enabled: true
      priority: 10
      config:
        registry_url: "https://packages.mylang.org"
        timeout: 30
```

### 2. Plugin-Specific Configuration

Plugins can access their configuration through the `AnalyzerContext`:

```go
func (a *MyLanguageAnalyzer) AnalyzeProject(ctx *scanner.AnalyzerContext) (*scanner.AnalysisResult, error) {
    // Access plugin configuration
    if config, ok := ctx.Config["registry_url"]; ok {
        registryURL := config.(string)
        // Use registry URL
    }
    
    // Implementation...
}
```

## Testing Plugins

### 1. Unit Tests

```go
package main

import (
    "testing"
    "typosentinel/internal/scanner"
)

func TestMyLanguageAnalyzer_CanAnalyze(t *testing.T) {
    analyzer := &MyLanguageAnalyzer{}
    
    projectInfo := &scanner.ProjectInfo{
        Type: "mylang",
        Path: "/test/project",
    }
    
    if !analyzer.CanAnalyze(projectInfo) {
        t.Error("Expected analyzer to handle mylang projects")
    }
}
```

### 2. Integration Tests

```go
func TestMyLanguageAnalyzer_ExtractDependencies(t *testing.T) {
    analyzer := &MyLanguageAnalyzer{}
    
    // Create test project
    projectInfo := &scanner.ProjectInfo{
        Type:         "mylang",
        Path:         "./testdata/sample-project",
        ManifestFile: "mylang.toml",
    }
    
    packages, err := analyzer.ExtractDependencies(projectInfo)
    if err != nil {
        t.Fatalf("Failed to extract dependencies: %v", err)
    }
    
    if len(packages) == 0 {
        t.Error("Expected to find dependencies")
    }
}
```

## Best Practices

### 1. Error Handling

- Always return meaningful error messages
- Use wrapped errors for better debugging
- Handle edge cases gracefully

```go
func (a *MyLanguageAnalyzer) ExtractDependencies(projectInfo *scanner.ProjectInfo) ([]*types.Package, error) {
    manifestPath := filepath.Join(projectInfo.Path, "mylang.toml")
    
    if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
        return nil, fmt.Errorf("manifest file not found: %s", manifestPath)
    }
    
    data, err := ioutil.ReadFile(manifestPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read manifest file %s: %w", manifestPath, err)
    }
    
    // Continue with parsing...
}
```

### 2. Performance

- Cache parsed data when possible
- Use streaming for large files
- Implement timeouts for network operations

### 3. Security

- Validate all input data
- Sanitize file paths
- Limit resource usage

### 4. Logging

```go
func (a *MyLanguageAnalyzer) AnalyzeProject(ctx *scanner.AnalyzerContext) (*scanner.AnalysisResult, error) {
    ctx.Logger.Info("Starting analysis for project", "path", ctx.ProjectInfo.Path)
    
    // Analysis logic...
    
    ctx.Logger.Debug("Found dependencies", "count", len(packages))
    return result, nil
}
```

## Example Plugins

See the `examples/plugins/` directory for complete plugin examples:

- `rust-analyzer/` - Rust/Cargo support
- `ruby-analyzer/` - Ruby/Gem support  
- `php-analyzer/` - PHP/Composer support

## Plugin Registry

Consider publishing your plugins to the TypoSentinel plugin registry:

1. Create a plugin manifest
2. Submit to the registry
3. Enable automatic updates

## Troubleshooting

### Common Issues

1. **Plugin not loading**: Check file permissions and plugin directory
2. **Interface mismatch**: Ensure you're implementing the correct interface version
3. **Build errors**: Verify Go version and dependencies
4. **Runtime errors**: Check logs and enable debug mode

### Debug Mode

```bash
# Enable debug logging
export TYPOSENTINEL_DEBUG=true
typosentinel scan --verbose
```

## Contributing

To contribute a plugin to the official TypoSentinel repository:

1. Fork the repository
2. Create your plugin in `plugins/`
3. Add tests and documentation
4. Submit a pull request

For questions and support, visit our [GitHub Discussions](https://github.com/typosentinel/typosentinel/discussions).