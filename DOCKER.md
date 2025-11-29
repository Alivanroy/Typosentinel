# Docker Usage Guide

This guide covers building and running TypoSentinel via Docker for both the CLI and API server.

## Prebuilt Image

- Pull: `docker pull vanali/typosentinel:latest`
- CLI scan: `docker run --rm vanali/typosentinel:latest scan /workspace --output json`
- API server: `docker run --rm -p 8080:8080 vanali/typosentinel:latest server`

## Build Locally

```bash
docker build -t typosentinel:latest .
```

Run CLI with a mounted project directory:

```bash
docker run --rm -v "$PWD:/workspace" typosentinel:latest scan /workspace --output json
```

Run API server:

```bash
docker run --rm -p 8080:8080 typosentinel:latest server
```

## Windows Path Conversion (Git Bash)

Git Bash rewrites volume paths. Disable path conversion when mounting:

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  --mount type=bind,source="$PWD",target=/workspace \
  vanali/typosentinel:latest scan /workspace --output json
```

## SBOM and SARIF Outputs

```bash
docker run --rm -v "$PWD:/workspace" vanali/typosentinel:latest scan /workspace --output sarif > scan.sarif.json
docker run --rm -v "$PWD:/workspace" vanali/typosentinel:latest scan /workspace --output cyclonedx > sbom.cyclonedx.json
docker run --rm -v "$PWD:/workspace" vanali/typosentinel:latest scan /workspace --output spdx > sbom.spdx.json
```

## Dependency Graph (DOT)

```bash
docker run --rm -v "$PWD:/workspace" vanali/typosentinel:latest \
  graph export /workspace --format dot --graph-style modern --rankdir LR > graph.dot
```

## Edge Algorithm (DIRT)

```bash
docker run --rm vanali/typosentinel:latest edge dirt lodash --max-depth 8 --risk-threshold 0.6 --include-graph > edge_dirt.txt
```

## Authentication for API

```bash
docker run --rm -p 8080:8080 \
  -e API_AUTH_ENABLED=true \
  -e API_KEYS=key1,key2 \
  vanali/typosentinel:latest server
```

## Compose (API + Database)

```bash
docker compose up -d
```

## Notes

- `CGO_ENABLED=1` is set in the Dockerfile for maximum compatibility.
- Use persistent volumes for data (e.g., `-v typosentinel-data:/data`).

