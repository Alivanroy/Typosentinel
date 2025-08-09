
#!/usr/bin/env python3
import os, sys, json, argparse
from pathlib import Path
from typing import List, Dict, Any

from hunter.fetchers.pypi import fetch_recent_pypi, fetch_pypi_auto
from hunter.fetchers.npm import fetch_npm_meta, fetch_npm_auto
from hunter.fetchers.gomod import fetch_go_meta, fetch_go_auto
from hunter.scanner import scan
from hunter.rules import is_cve_candidate

def parse_list(arg: str) -> List[str]:
    return [x.strip() for x in arg.split(",") if x.strip()]

def main():
    ap = argparse.ArgumentParser(description="Typosentinel CVE Hunter — discover suspicious packages and flag potential CVE candidates")
    ap.add_argument("--ecosystems", default="pypi,npm,go", help="comma list: pypi,npm,go")
    ap.add_argument("--names", help="comma list of package names to seed (optional)")
    ap.add_argument("--npm-names", help="comma list of npm packages (optional)")
    ap.add_argument("--pypi-names", help="comma list of PyPI packages (optional)")
    ap.add_argument("--go-modules", help="comma list of Go modules (optional)")
    ap.add_argument("--policy", default="balanced", help="Typosentinel policy: fast|balanced|paranoid")
    ap.add_argument("--out-json", default="out/candidates.json", help="write candidate results")
    ap.add_argument("--out-all", default="out/all_scans.json", help="write all scan results")
    args = ap.parse_args()

    ecosystems = parse_list(args.ecosystems)
    seed_all = parse_list(args.names or "")
    npm_names = parse_list(args.npm_names or "")
    pypi_names = parse_list(args.pypi_names or "")
    go_modules = parse_list(args.go_modules or "")

    auto_mode = False
    if not any([seed_all, npm_names, pypi_names, go_modules]):
        auto_mode = True

    targets: List[Dict, Any] = []

    # Auto-fetch mode: pull newest/updated packages when no names were provided
    if auto_mode:
        print("🔍 Auto-fetching: latest PyPI/npm/Go packages ...")
        if "pypi" in ecosystems:
            print("📦 Fetching latest PyPI packages...")
            pypi_targets = fetch_pypi_auto(limit=20)
            print(f"✅ Found {len(pypi_targets)} PyPI packages")
            targets += pypi_targets
        if "npm" in ecosystems:
            print("📦 Fetching latest npm packages...")
            npm_targets = fetch_npm_auto(limit=20)
            print(f"✅ Found {len(npm_targets)} npm packages")
            targets += npm_targets
        if "go" in ecosystems:
            print("📦 Fetching latest Go modules...")
            go_targets = fetch_go_auto(limit=10)
            print(f"✅ Found {len(go_targets)} Go modules")
            targets += go_targets
    else:
        print("🎯 Using provided package names...")
        if "pypi" in ecosystems and (seed_all or pypi_names):
            print(f"📦 Fetching PyPI metadata for {len(seed_all + pypi_names)} packages...")
            targets += fetch_recent_pypi(seed_all + pypi_names)
        if "npm" in ecosystems and (seed_all or npm_names):
            print(f"📦 Fetching npm metadata for {len(seed_all + npm_names)} packages...")
            targets += fetch_npm_meta(seed_all + npm_names)
        if "go" in ecosystems and (seed_all or go_modules):
            print(f"📦 Fetching Go metadata for {len(seed_all + go_modules)} modules...")
            targets += fetch_go_meta(seed_all + go_modules)

    if not targets:
        print("❌ No targets to scan. Provide --names/--npm-names/--pypi-names/--go-modules or wire to registry feeds.", file=sys.stderr)
        sys.exit(1)

    print(f"🎯 Total targets to scan: {len(targets)}")
    all_results = []
    candidates = []

    for i, t in enumerate(targets, 1):
        eco = t["ecosystem"]
        name = t["name"]
        version = t.get("version")
        print(f"🔍 [{i}/{len(targets)}] Scanning {eco}:{name} (v{version or 'latest'})...")
        
        try:
            res = scan(eco, name, version, policy=args.policy)
            print(f"   ⏱️  Scan completed in {res.latency:.3f}s - Decision: {res.decision}, Risk: {res.risk:.2f}")
            
            if res.signals:
                print(f"   🚨 Signals detected: {', '.join(res.signals)}")
            
            item = {
                "ecosystem": eco, "name": name, "version": version,
                "decision": res.decision, "risk": res.risk, "latency": res.latency,
                "signals": res.signals, "stdout": res.stdout, "stderr": res.stderr
            }
            all_results.append(item)
            
            cand, reasons = is_cve_candidate(t, res)
            if cand:
                item["reasons"] = reasons
                candidates.append(item)
                print(f"🚨 [CVE CANDIDATE] {eco}:{name} risk={res.risk:.2f} decision={res.decision}")
                print(f"   📋 Reasons: {', '.join(reasons)}")
            else:
                print(f"   ✅ Clean package")
                
        except Exception as e:
            print(f"   ❌ Error scanning {eco}:{name}: {str(e)}")
            continue

    print(f"\n📊 HUNT SUMMARY:")
    print(f"   📦 Total packages scanned: {len(all_results)}")
    print(f"   🚨 CVE candidates found: {len(candidates)}")
    print(f"   ✅ Clean packages: {len(all_results) - len(candidates)}")
    
    out_all = Path(args.out_all); out_all.parent.mkdir(parents=True, exist_ok=True)
    out_all.write_text(json.dumps(all_results, indent=2), encoding="utf-8")

    out_c = Path(args.out_json); out_c.parent.mkdir(parents=True, exist_ok=True)
    out_c.write_text(json.dumps(candidates, indent=2), encoding="utf-8")

    print(f"\n💾 Results saved:")
    print(f"   📄 All scans: {out_all}")
    print(f"   🎯 CVE candidates: {out_c}")
    
    if candidates:
        print(f"\n🚨 CVE CANDIDATES SUMMARY:")
        for c in candidates:
            print(f"   • {c['ecosystem']}:{c['name']} (risk: {c['risk']:.2f}, decision: {c['decision']})")
    else:
        print(f"\n✅ No CVE candidates found - all packages appear clean!")

if __name__ == "__main__":
    main()
