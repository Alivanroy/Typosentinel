
from typing import Dict, Any, List, Tuple

def is_cve_candidate(package: Dict[str, Any], scan_result) -> Tuple[bool, List[str]]:
    reasons: List[str] = []

    if scan_result.decision == "block" and scan_result.risk >= 0.9:
        reasons.append("High risk (>=0.9) with decision=block")

    s = set(scan_result.signals)
    suspicious = {"homoglyph", "keyboard", "levenshtein", "registry_mismatch",
                  "maintainer_change", "provenance_mismatch", "unexpected_network_domain",
                  "code_injection_pattern", "download_spike"}
    hit = s.intersection(suspicious)
    if hit:
        reasons.append(f"Suspicious signals: {', '.join(sorted(hit))}")

    if package.get("updated"):
        reasons.append("Recent update (metadata present)")

    if scan_result.decision == "review" and scan_result.risk >= 0.85 and hit:
        reasons.append("High risk review with strong signals")

    return (len(reasons) > 0, reasons)
