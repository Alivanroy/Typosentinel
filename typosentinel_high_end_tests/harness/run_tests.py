#!/usr/bin/env python3
import os, sys, time, json, subprocess, shutil, argparse, hashlib
from pathlib import Path

try:
    import yaml
except Exception:
    yaml = None

TYPOSENTINEL_BIN = os.environ.get("TYPOSENTINEL_BIN", "typosentinel")

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = ROOT / "scenarios"
EXPECTED_DIR = ROOT / "scenarios" / "expected"
OUT_DIR = ROOT / "out"
OUT_DIR.mkdir(exist_ok=True)

def load_yaml(p):
    global yaml
    if yaml is None:
        raise SystemExit("pyyaml is required: pip install pyyaml")
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def run_cli(args, timeout=60):
    cmd = [TYPOSENTINEL_BIN] + args
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise SystemExit(f"Typosentinel binary not found: {TYPOSENTINEL_BIN}")
    dt = time.time() - t0
    return proc.returncode, proc.stdout, proc.stderr, dt

def eval_scenario(scn):
    name = scn["name"]
    suite = scn.get("suite", "core")
    args = scn["cli_args"]
    expect = scn["expect"]
    rc, out, err, dt = run_cli(args)
    result = {
        "name": name, "suite": suite, "rc": rc, "stdout": out, "stderr": err, "latency_sec": dt,
        "passed": True, "reasons": []
    }

    # Expectations
    if "expect_rc" in expect and rc != expect["expect_rc"]:
        result["passed"] = False
        result["reasons"].append(f"Expected RC {expect['expect_rc']}, got {rc}")
    if "latency_p95_sec" in expect and dt > expect["latency_p95_sec"]:
        result["passed"] = False
        result["reasons"].append(f"Latency {dt:.2f}s exceeds budget {expect['latency_p95_sec']}s")

    # Simple JSON parsing if output is JSON-like
    # Fallback to string search for signals/scores
    data = {}
    try:
        data = json.loads(out)
    except Exception:
        # try to find score and decision in text
        pass

    # Score expectation
    min_score = expect.get("min_score")
    decision_contains = expect.get("decision_contains")
    signals_contains = expect.get("signals_contains", [])

    if min_score is not None:
        score = None
        if isinstance(data, dict):
            score = data.get("risk_score") or data.get("overall_score")
        if score is None:
            # try regex-less heuristics
            for line in out.splitlines():
                if "score" in line.lower():
                    try:
                        score = float("".join(ch for ch in line if ch.isdigit() or ch == "."))
                        break
                    except Exception:
                        pass
        if score is None or float(score) < float(min_score):
            result["passed"] = False
            result["reasons"].append(f"Score {score} < min_score {min_score}")

    if decision_contains:
        if decision_contains.lower() not in out.lower():
            result["passed"] = False
            result["reasons"].append(f"Decision text missing: {decision_contains}")

    for sig in signals_contains:
        if sig.lower() not in out.lower():
            result["passed"] = False
            result["reasons"].append(f"Signal missing: {sig}")

    return result

def discover_scenarios(suite=None):
    paths = []
    if suite is None or suite == "core":
        paths += list((SCENARIOS_DIR / "core").glob("*.yaml"))
    if suite is None or suite == "solarwinds_like":
        paths += list((SCENARIOS_DIR / "solarwinds_like").glob("*.yaml"))
    return sorted(paths)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", choices=["core","solarwinds_like"], help="Run a specific suite")
    ap.add_argument("--all", action="store_true", help="Run all suites")
    ap.add_argument("--json", help="Write results to JSON file")
    args = ap.parse_args()

    suite = None if args.all or not args.suite else args.suite
    scn_files = discover_scenarios(suite)

    results = []
    failed = 0
    for f in scn_files:
        scn = load_yaml(f)
        res = eval_scenario(scn)
        results.append(res)
        if not res["passed"]:
            failed += 1
        print(f"[{'PASS' if res['passed'] else 'FAIL'}] {res['suite']}/{res['name']}  ({res['latency_sec']:.2f}s)")
        for r in res["reasons"]:
            print("  -", r)

    summary = {
        "total": len(results),
        "failed": failed,
        "passed": len(results) - failed,
        "timestamp": time.time()
    }
    print(f"\nSummary: {summary['passed']}/{summary['total']} passed; {summary['failed']} failed")

    if args.json:
        outp = Path(args.json)
        outp.parent.mkdir(parents=True, exist_ok=True)
        with open(outp, "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "results": results}, f, indent=2)

    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
