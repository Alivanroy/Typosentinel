#!/usr/bin/env python3
import os, sys, json, re
from pathlib import Path
from datetime import datetime

REGEXES = [r"Function\(", r"child_process", r"exec\(", r"system\(", r"XMLHttpRequest",
           r"fetch\(", r"atob\(", r"btoa\(", r"new\s+WebSocket", r"eval\(", r"process\.env", r"\\u[0-9a-fA-F]{4}"]

def load_lines(path: Path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

def main():
    if len(sys.argv) < 4:
        print("Usage: diff_npm.py <out_dir> <suspect> <legit> [grep_hits.json]", file=sys.stderr)
        sys.exit(2)
    out_dir = Path(sys.argv[1])
    suspect = sys.argv[2]
    legit = sys.argv[3]
    grep_json = Path(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else None

    diff_txt = out_dir/"diff.txt"
    suspect_sha = (out_dir/"suspect_sha256.txt").read_text(encoding="utf-8", errors="ignore").strip() if (out_dir/"suspect_sha256.txt").exists() else ""
    legit_sha = (out_dir/"legit_sha256.txt").read_text(encoding="utf-8", errors="ignore").strip() if (out_dir/"legit_sha256.txt").exists() else ""
    legit_selected = (out_dir/"legit_selected.txt").read_text(encoding="utf-8", errors="ignore").strip() if (out_dir/"legit_selected.txt").exists() else ""
    suspect_meta = load_lines(out_dir/"suspect_meta.json")

    # Build focus list from grep hits (relative paths 'package/...')
    focus_files = set()
    if grep_json and grep_json.exists():
        try:
            hits = json.loads(grep_json.read_text(encoding="utf-8"))
            for h in hits:
                f = h.get("file")
                if f:
                    # Diff paths are like a/ and b/ prefixes; keep relative file
                    focus_files.add(f)
        except Exception:
            pass

    lines = load_lines(diff_txt)
    # Extract only hunks that match risk regexes or focus_files
    interesting = []
    pattern = re.compile("|".join(REGEXES), re.IGNORECASE)
    hunk = []
    current_file = None
    for ln in lines:
        if ln.startswith("--- ") or ln.startswith("+++ "):
            current_file = ln.split("\t")[0].split(" ",1)[1] if " " in ln else None
        if ln.startswith("@@"):
            # flush previous hunk
            if hunk:
                interesting.extend(hunk)
                hunk = []
        # collect lines
        if ln.startswith("@@") or ln.startswith("--- ") or ln.startswith("+++ ") or ln.startswith("+") or ln.startswith("-") or ln.startswith(" "):
            take = False
            if pattern.search(ln):
                take = True
            if focus_files and current_file:
                # diff uses paths like LEG_DIR/... and SUS_DIR/...
                for f in focus_files:
                    if f in current_file:
                        take = True; break
            if take:
                hunk.append(ln)

    report = out_dir/"report.md"
    with report.open("w", encoding="utf-8") as f:
        f.write(f"# Typosentinel Diff Report — {suspect} vs {legit}\n\n")
        f.write(f"**Generated:** {datetime.utcnow().isoformat()}Z\n\n")
        f.write("## Summary\n")
        f.write(f"- Suspect: `{suspect}`  \n- Legit: `{legit_selected}`  \n\n")
        f.write("## Tarball Hashes\n")
        f.write(f"- Suspect: `{suspect_sha}`\n")
        f.write(f"- Legit: `{legit_sha}`\n\n")
        if grep_json and grep_json.exists():
            f.write(f"## Focused by grep hits: `{grep_json}`\n\n")
        f.write("## High-Risk Differences (filtered)\n\n")
        if interesting:
            f.write("```\n")
            for ln in interesting[:2000]:
                f.write(ln + "\n")
            f.write("```\n")
        else:
            f.write("_No filtered differences matched indicators; see full diff below._\n")

        f.write("\n## Full Unified Diff\n\n")
        f.write("```\n")
        for ln in lines[:4000]:
            f.write(ln + "\n")
        f.write("```\n")
    print(f"Wrote report: {report}")

if __name__ == "__main__":
    main()
