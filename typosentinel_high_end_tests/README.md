# Typosentinel — High-End Test Harness (with SolarWinds-like Scenarios)

This package provides a comprehensive, **real-life test suite** to validate Typosentinel across ecosystems,
including **typosquatting**, **dependency confusion**, **homoglyph**, **phonetic**, **maintainer hijack**, and
**SolarWinds-style supply-chain** scenarios.

## Contents
- `harness/` — Python test runner and mock registries.
- `scenarios/` — YAML definitions for each scenario with inputs & expected outcomes.
- `scripts/` — Shell helpers to execute the CLI and capture outputs.
- `splunk_examples/` — Example HEC events & Splunk sourcetype field mapping.
- `README_assets/` — Diagrams and notes to explain attack flows (placeholders).

## How to run (quick start)
1. Ensure the Typosentinel CLI is available on PATH (binary named `typosentinel`) or set `TYPOSENTINEL_BIN=/path/to/typosentinel`.
2. Install Python deps (only standard library used by default). If you want `rich` output: `pip install rich pyyaml`.
3. Run:
   ```bash
   python3 harness/run_tests.py --all
   ```
   or run a specific suite:
   ```bash
   python3 harness/run_tests.py --suite core
   python3 harness/run_tests.py --suite solarwinds_like
   ```

## What’s measured
- Detection correctness (pass/block) per scenario
- Score thresholds (e.g., confidence > 0.9 for known malicious)
- Latency budgets (p95 < 3s)
- Logging completeness (all key signals captured)

## CI integration (GitHub Actions / GitLab CI)
- Add a step to run: `python3 harness/run_tests.py --all --json out/results.json`
- Upload artifacts and fail the job if any scenario deviates from expected values.

## Note
The package includes **benign fixtures** only; no real malware or harmful content.
