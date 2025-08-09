# Coordinated Vulnerability Disclosure Report — npm:webpack2

**Date generated:** 2025-08-09 20:53:37Z  
**Reporter:** Typosentinel team (<contact>)

> We could not confirm a public npm package named `webpack2`. If private/removed, include evidence (mirror URLs, internal registry logs).

## Summary
Typosentinel flagged `webpack2` as a **high-confidence typosquatting** package mimicking `webpack`. Decision: **BLOCK**. Risk score: **0.975** (internal).

## Technical Evidence (if available)
- Tarball SHA256: `<paste>`
- Indicators: `<paste from grep_hits>`
- Typosentinel JSON: attach `out/webpack2/typosentinel.json` (or error output)

## Reproduction
```bash
npm view webpack2 --json || true
npm pack webpack2 || true
typosentinel scan --ecosystem npm --package webpack2 --format json --policy paranoid || true
```
