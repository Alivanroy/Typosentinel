# TypoSentinel User Guide

## Installation

### Binary
- Download platform binary from GitHub Releases and place on PATH

### From Source
```bash
git clone https://github.com/Alivanroy/Typosentinel.git
cd Typosentinel
go build -o typosentinel .
```

### Docker
```bash
docker build -t typosentinel-api . && docker run --rm -p 8080:8080 typosentinel-api
```

## CLI Usage
```bash
./typosentinel version
./typosentinel scan . --output json --supply-chain --advanced
```

### CLI Flags
- `--output {json|sarif|table}`: output format
- `--supply-chain`: enable supply chain analysis
- `--advanced`: enhanced detection algorithms
- `--threshold <0..1>`: similarity threshold
- `--registry <npm|pypi|go|maven>`: force registry when needed

## API Server
```bash
./typosentinel server --port 8080
```

### Authentication
- `API_AUTH_ENABLED=true`
- `API_KEYS=key1,key2`
- Send `Authorization: Bearer key1`

## Configuration
- Environment variables for API auth
- CLI flags for output, supply chain analysis, and detection options

## CI/CD Integration
- Use reusable workflow `.github/workflows/supply-chain-firewall.yml`
- Or build and run CLI in your pipelines to enforce policies

## Troubleshooting
- `401 Unauthorized`: ensure `API_KEYS` set and header included
- `429 Too Many Requests`: reduce request rate
- Docker: map port `-p 8080:8080`; set env vars with `-e`
