#!/usr/bin/env bash
set -euo pipefail
FILE=${1:-coverage.out}
if [[ ! -f "$FILE" ]]; then
  echo "coverage file not found: $FILE"; exit 1
fi
TOTAL=$(go tool cover -func "$FILE" | tail -n1 | awk '{print $3}' | tr -d '%')
REQ=${COVERAGE_MIN:-10}
TOTAL_INT=${TOTAL%.*}
if (( $(echo "$TOTAL < $REQ" | bc -l) )); then
  echo "coverage $TOTAL% below minimum $REQ%"; exit 1
fi
echo "coverage $TOTAL% meets minimum $REQ%"

