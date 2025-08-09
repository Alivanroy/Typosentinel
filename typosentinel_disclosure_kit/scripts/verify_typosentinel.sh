#!/usr/bin/env bash
set -euo pipefail
PKG="${1:-}"
if [[ -z "$PKG" ]]; then echo "Usage: $0 <npm-package-name>" >&2; exit 2; fi
BIN="${TYPOSENTINEL_BIN:-typosentinel}"
OUT="out/$PKG"; mkdir -p "$OUT"
if command -v "$BIN" >/dev/null 2>&1; then
  "$BIN" scan --ecosystem npm --package "$PKG" --format json --policy paranoid > "$OUT/typosentinel.json" || true
  echo "[*] Typosentinel JSON -> $OUT/typosentinel.json"
else
  echo "[!] Typosentinel binary not found. Set TYPOSENTINEL_BIN or add to PATH." >&2
fi
