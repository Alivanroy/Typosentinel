# Rust/Cargo Analyzer Plugin

This is an example plugin for TypoSentinel that adds support for analyzing Rust projects using the Cargo package manager.

## Features

- Parses `Cargo.toml` files to extract dependencies
- Analyzes `Cargo.lock` files for exact version information
- Supports workspace projects
- Detects transitive dependencies
- Validates Rust project structure

## Building the Plugin

```bash
# Build the plugin
go build -buildmode=plugin -o rust-analyzer.so .
```

## Installation

1. Build the plugin (see above)
2. Copy `rust-analyzer.so` to your TypoSentinel plugins directory
3. Configure TypoSentinel to load the plugin:

```yaml
# .typosentinel.yaml
plugins:
  enabled: true
  plugin_dir: "./plugins"
  auto_load: true
  plugins:
    - name: "rust-cargo"
      path: "./plugins/rust-analyzer.so"
      enabled: true
```

## Supported Project Structure

The plugin can analyze Rust projects with the following structure:

```
my-rust-project/
├── Cargo.toml          # Required: Package manifest
├── Cargo.lock          # Optional: Lock file with exact versions
├── src/
│   ├── main.rs         # Binary crate entry point
│   └── lib.rs          # Library crate entry point
└── examples/           # Optional: Example code
```

## Workspace Support

The plugin also supports Cargo workspaces:

```
my-workspace/
├── Cargo.toml          # Workspace manifest
├── member1/
│   ├── Cargo.toml
│   └── src/
└── member2/
    ├── Cargo.toml
    └── src/
```

## Dependency Sources

The plugin can extract dependencies from:

- **Cargo.toml**: Direct dependencies with version requirements
- **Cargo.lock**: Exact versions of all dependencies (including transitive)
- **Git dependencies**: Dependencies from Git repositories
- **Path dependencies**: Local path dependencies
- **Registry dependencies**: Dependencies from crates.io or custom registries

## Configuration

The plugin supports the following configuration options:

```yaml
plugins:
  plugins:
    - name: "rust-cargo"
      path: "./plugins/rust-analyzer.so"
      enabled: true
      config:
        # Custom registry URL (default: crates.io)
        registry_url: "https://crates.io"
        
        # Include dev dependencies (default: false)
        include_dev_deps: false
        
        # Include build dependencies (default: false)
        include_build_deps: false
        
        # Maximum workspace depth (default: 5)
        max_workspace_depth: 5
```

## Testing

Run the plugin tests:

```bash
go test -v
```

## Example Output

When analyzing a Rust project, the plugin will extract dependencies like:

```json
{
  "packages": [
    {
      "name": "serde",
      "version": "1.0.193",
      "registry": "crates.io",
      "type": "rust",
      "metadata": {
        "source": "Cargo.toml",
        "checksum": "abc123..."
      }
    },
    {
      "name": "tokio",
      "version": "1.35.0",
      "registry": "crates.io",
      "type": "rust",
      "metadata": {
        "source": "Cargo.lock",
        "transitive": true
      }
    }
  ],
  "project_type": "rust",
  "analyzer_name": "rust-cargo",
  "metadata": {
    "has_lockfile": true,
    "cargo_metadata": {
      "name": "my-project",
      "version": "0.1.0",
      "edition": "2021"
    }
  }
}
```

## Limitations

- This is a simplified example implementation
- For production use, consider using proper TOML parsing libraries
- Git dependencies are detected but not fully analyzed
- Workspace analysis is basic and could be enhanced

## Contributing

To improve this plugin:

1. Add proper TOML parsing using `github.com/BurntSushi/toml`
2. Implement full workspace member analysis
3. Add support for custom registries
4. Enhance Git dependency handling
5. Add more comprehensive tests

## License

This plugin is part of the TypoSentinel project and follows the same license.