#!/usr/bin/env bash
set -euo pipefail
docker compose up -d --build
make test
pytest tests/detection/python -q
pytest tests/scanning/integration -q