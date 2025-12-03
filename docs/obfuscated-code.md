# Obfuscated Code Detection

TypoSentinel flags high-entropy and obfuscated code segments that may hide malicious payloads. Review flagged files and verify encoded content is legitimate.

## Indicators
- High Shannon entropy in file or windowed spans
- Long base64/hex strings and decoder chains
- Frequent use of `eval`/dynamic execution

## Guidance
- Inspect decoded payloads, minimize dynamic execution, and validate sources. Remove obfuscated code unless strictly necessary.

## Remediation Steps
- Identify the source of obfuscation (build step, dependency, vendor code)
- Decode base64/hex to verify content; remove suspicious payloads
- Replace obfuscated libraries with reputable alternatives
- Enforce lint rules or CI checks to block obfuscation in PRs

## Examples
```js
// Suspicious: multiple eval and large base64 payloads
const b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="; // large payload
const decoded = atob(b64);
eval(decoded); // Avoid

// Safer alternative: no dynamic evaluation
console.log("process payload safely");
```

### Python Obfuscation Examples
```python
# Base64 decode then exec — avoid
import base64
payload = base64.b64decode("cHJpbnQoJ2V4ZWMnKQ==")
exec(payload)  # Dangerous

# Hex/unicode escape chains
code = "\x70\x72\x69\x6e\x74('run')"
eval(code)  # Dangerous

# Safer alternative
def run():
    print('run')
run()
```

### Remediation for Python
- remove base64/hex encoded executable strings; store data, not code.
- replace `exec`/`eval` with explicit functions and whitelisted modules.
- add static analysis (bandit, flake8) rules to block dynamic execution.
