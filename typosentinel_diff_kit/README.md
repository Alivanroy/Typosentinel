
# Typosentinel NPM Diff Kit

This kit automates **forensic diffing** between a **suspicious package** (e.g., `express2`) and its **legitimate counterpart** (e.g., `express`).
It fetches tarballs via `npm pack`, extracts them, runs `diff -ru`, and generates a **Markdown report** highlighting risky changes.

> Run in a disposable environment. Do **not** `npm install` the suspicious package.

## Quick Start
```bash
# Requirements: npm, tar, diffutils, sha256sum, python3
# Optional: Typosentinel binary in PATH (or TYPOSENTINEL_BIN env)

# 1) Diff express2 (suspect) vs express (legit), auto-selecting legit version
bash scripts/diff_npm.sh express2 express

# 2) (Optional) Provide grep hits JSON to focus the report
#    Use the grep_hits.json produced by our triage kit:
bash scripts/diff_npm.sh express2 express out/express2/grep_hits.json

# Outputs:
# - out/express2_vs_express/report.md
# - out/express2_vs_express/diff.txt (full unified diff)
# - extracted tarballs + SHA256 hashes
```

## Version Selection
By default, the script picks the **closest legit version**:
- If the suspicious package claims version `X.Y.Z`, it chooses the **nearest major/minor** of the legit package.
- You can override by setting `LEGIT_VERSION` env:
```bash
LEGIT_VERSION=4.18.3 bash scripts/diff_npm.sh express2 express
```

## Files
- `scripts/diff_npm.sh` — main runner (shell utilities + `diff`)
- `scripts/diff_npm.py` — report generator (parses diffs, optional grep focus)
- `tools/regexes.txt` — indicator patterns (same as triage kit)
