
import os, json, subprocess, time
from dataclasses import dataclass
from typing import List, Optional

TYPOSENTINEL_BIN = os.environ.get("TYPOSENTINEL_BIN", "typosentinel")

@dataclass
class ScanOutput:
    ok: bool
    decision: str
    risk: float
    latency: float
    stdout: str
    stderr: str
    signals: List[str]

def scan(ecosystem: str, name: str, version: Optional[str]=None, policy: str="balanced") -> ScanOutput:
    args = [TYPOSENTINEL_BIN, "analyze", "--output", "json"]
    if ecosystem == "pypi":
        args += [name, "pypi"]
    elif ecosystem == "npm":
        args += [name, "npm"]
    elif ecosystem == "go":
        args += [name, "go"]
    else:
        args += [name, "pypi"]  # default to pypi

    print(f"      🔧 Executing: {' '.join(args)}")
    t0 = time.time()
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=30)
        print(f"      📤 Exit code: {p.returncode}")
        if p.stderr:
            print(f"      ⚠️  Stderr: {p.stderr.strip()}")
    except FileNotFoundError:
        print(f"      ❌ Binary not found: {TYPOSENTINEL_BIN}")
        return ScanOutput(False, "error", 0.0, 0.0, "", f"{TYPOSENTINEL_BIN} not found", [])
    except subprocess.TimeoutExpired:
        print(f"      ⏰ Scan timeout after 30s")
        return ScanOutput(False, "timeout", 0.0, 30.0, "", "scan timeout", [])

    dt = time.time() - t0
    decision = "unknown"
    risk = 0.0
    signals: List[str] = []
    try:
        j = json.loads(p.stdout.strip())
        # Map threat_level to decision
        threat_level = j.get("threat_level", "none")
        if threat_level == "critical":
            decision = "block"
        elif threat_level == "high":
            decision = "review"
        elif threat_level in ["medium", "low"]:
            decision = "review"
        else:
            decision = "allow"
        
        # Use confidence as risk score
        risk = float(j.get("confidence", 0.0))
        
        # Extract signals from threats evidence
        threats = j.get("threats", [])
        for threat in threats:
            evidence = threat.get("evidence", [])
            for ev in evidence:
                ev_type = ev.get("type", "")
                if ev_type:
                    signals.append(ev_type.lower())
        
        # Add threat types as signals
        for threat in threats:
            threat_type = threat.get("type", "")
            if threat_type:
                signals.append(threat_type.lower())
                
    except Exception:
        lo = p.stdout.lower()
        if "critical" in lo: decision = "block"
        elif "high" in lo: decision = "review"
        elif "medium" in lo or "low" in lo: decision = "review"
        else: decision = "allow"

    return ScanOutput(True, decision, risk, dt, p.stdout, p.stderr, signals)
