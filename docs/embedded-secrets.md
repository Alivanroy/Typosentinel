# Embedded Secrets Detection

TypoSentinel detects credentials embedded in package contents (e.g., API keys, tokens). Embedded secrets pose a high risk.

## Examples
- AWS access keys and secret keys
- JWT tokens and OAuth credentials

## Guidance
- Remove secrets from source; rotate credentials immediately; use environment variables and secret managers.

## Remediation Steps
- Search and remove all occurrences of leaked credentials
- Rotate keys/tokens immediately and invalidate compromised secrets
- Use environment variables or secret managers (e.g., Vault, AWS Secrets Manager)
- Add pre-commit/CI checks to block secrets in commits

## Examples
```env
# Good: use environment variables
API_KEY=${API_KEY}

# Bad: hardcoded secret
API_KEY=AKIA1234567890ABCD
```
