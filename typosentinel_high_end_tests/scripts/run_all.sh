#!/usr/bin/env bash
set -euo pipefail
python3 harness/run_tests.py --all --json out/results.json
echo "Results written to out/results.json"
