#!/usr/bin/env bash
set -euo pipefail

SUSPECT="${1:-}"
LEGIT="${2:-}"
GREP_JSON="${3:-}"

if [[ -z "$SUSPECT" || -z "$LEGIT" ]]; then
  echo "Usage: $0 <suspect-pkg> <legit-pkg> [grep_hits.json]" >&2
  exit 2
fi

OUT="out/${SUSPECT}_vs_${LEGIT}"
mkdir -p "$OUT"

echo "[*] npm view (suspect): $SUSPECT"
npm view "$SUSPECT" dist-tags versions time maintainers description repository homepage --json > "$OUT/suspect_meta.json" || true

echo "[*] npm pack (suspect): $SUSPECT"
if npm pack "$SUSPECT" > "$OUT/suspect_pack.out" 2>&1; then
  SUS_TGZ="$(awk '{print $NF}' "$OUT/suspect_pack.out" | tail -n1)"
  mv "$SUS_TGZ" "$OUT/" || true
  SUS_TGZ="$OUT/$(basename "$SUS_TGZ")"
  shasum -a 256 "$SUS_TGZ" | tee "$OUT/suspect_sha256.txt"
  mkdir -p "$OUT/suspect"; tar -xf "$SUS_TGZ" -C "$OUT/suspect"
else
  echo "[!] npm pack failed for suspect ($SUSPECT). See $OUT/suspect_pack.out" >&2
fi

# Determine legit version
LEGIT_VER="${LEGIT_VERSION:-}"
if [[ -z "$LEGIT_VER" ]]; then
  echo "[*] Using latest legit version"
  LEGIT_VER=$(npm view "$LEGIT" version)
fi
echo "$LEGIT@$LEGIT_VER" | tee "$OUT/legit_selected.txt"

echo "[*] npm pack (legit): $LEGIT@$LEGIT_VER"
npm pack "$LEGIT@$LEGIT_VER" > "$OUT/legit_pack.out" 2>&1 || true
LEG_TGZ="$(awk '{print $NF}' "$OUT/legit_pack.out" | tail -n1)"
mv "$LEG_TGZ" "$OUT/" || true
LEG_TGZ="$OUT/$(basename "$LEG_TGZ")"
shasum -a 256 "$LEG_TGZ" | tee "$OUT/legit_sha256.txt"
mkdir -p "$OUT/legit"; tar -xf "$LEG_TGZ" -C "$OUT/legit"

# Find the package root (npm packs under 'package/')
SUS_DIR="$OUT/suspect/package"
LEG_DIR="$OUT/legit/package"

echo "[*] Running diff -ru"
diff -ru --strip-trailing-cr "$LEG_DIR" "$SUS_DIR" > "$OUT/diff.txt" || true

echo "[*] Generating report"
python3 scripts/diff_npm.py "$OUT" "${SUSPECT}" "${LEGIT}" "${GREP_JSON:-}"

echo "[*] Done. See $OUT/report.md"
