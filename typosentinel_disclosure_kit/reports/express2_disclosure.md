# Coordinated Vulnerability Disclosure Report — npm:express2

**Date generated:** 2025-08-09 20:53:37Z  
**Reporter:** Typosentinel team (<contact>)

## Summary
Typosentinel flagged `express2` as a **high-confidence typosquatting** package mimicking `express` with risky patterns (Function constructor, exec/child_process, unicode escapes). Decision: **BLOCK**. Risk score: **0.975**.

## Package Metadata
- Name: `express2` (npm)
- Last observed version: 5.15.3 (per npm profile)
- Maintainers: 1
- Publication timestamps: attach from `out/express2/meta.json`

## Technical Evidence
- Tarball SHA256: `<paste from out/express2/sha256.txt>`
- Indicators: attach `out/express2/grep_hits.txt` or `grep_hits.json`
- Typosentinel JSON: attach `out/express2/typosentinel.json`

## Reproduction
```bash
npm view express2 --json
npm pack express2
tar -xf express2-*.tgz -C /tmp/express2_pkg
grep -RInE -f tools/regexes.txt /tmp/express2_pkg
typosentinel scan --ecosystem npm --package express2 --format json --policy paranoid
```

## Impact
- Potential RCE during build/runtime; secrets exposure via `process.env`

## Mitigations
- Quarantine/unpublish; notify impacted users; create block rules for name-suffix typos

## CVE
Request CVE via npm/GitHub CNA after validation.
