#!/usr/bin/env bash
set -euo pipefail
PKG="${1:-}"
if [[ -z "$PKG" ]]; then echo "Usage: $0 <npm-package-name>" >&2; exit 2; fi
OUT="out/$PKG"; mkdir -p "$OUT"
echo "[*] npm view metadata: $PKG"
npm view "$PKG" dist-tags versions time maintainers description repository homepage --json > "$OUT/meta.json" || {
  echo "[!] npm view failed for $PKG. See $OUT/meta.json" >&2
}
echo "[*] npm pack (no install): $PKG"
if npm pack "$PKG" > "$OUT/pack.out" 2>&1; then
  TGZ="$(awk '{print $NF}' "$OUT/pack.out" | tail -n1)"
  if [[ -f "$TGZ" ]]; then
    mv "$TGZ" "$OUT/"; TGZ="$OUT/$(basename "$TGZ")"
    echo "[*] sha256"; sha256sum "$TGZ" | tee "$OUT/sha256.txt"
    echo "[*] extract"; mkdir -p "$OUT/extracted"; tar -xf "$TGZ" -C "$OUT/extracted"
    echo "[*] grep indicators"; REGEX_FILE="tools/regexes.txt"
    if [[ -f "$REGEX_FILE" ]]; then
      GREP_PAT="$(paste -sd'|' "$REGEX_FILE")"
      grep -RInE "$GREP_PAT" "$OUT/extracted" | tee "$OUT/grep_hits.txt" || true
    fi
  fi
else
  echo "[!] npm pack failed for $PKG — see $OUT/pack.out" >&2
fi
echo "[*] run Typosentinel"; bash scripts/verify_typosentinel.sh "$PKG" || true
echo "[*] done. outputs under $OUT"
