#!/usr/bin/env python3
import os, sys, json, subprocess, tarfile, hashlib, re
from pathlib import Path
REGEXES = [r"Function\(", r"child_process", r"exec\(", r"system\(", r"XMLHttpRequest",
           r"fetch\(", r"atob\(", r"btoa\(", r"new\s+WebSocket", r"eval\(", r"process\.env", r"\\u[0-9a-fA-F]{4}"]
def run(cmd): return subprocess.run(cmd, capture_output=True, text=True)
def sha256sum(p: Path) -> str:
  h = hashlib.sha256(); 
  with p.open("rb") as f:
    for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
  return h.hexdigest()
def main():
  if len(sys.argv) < 2: print("Usage: triage_npm.py <package>", file=sys.stderr); sys.exit(2)
  pkg = sys.argv[1]; out = Path("out")/pkg; out.mkdir(parents=True, exist_ok=True)
  mv = run(["npm", "view", pkg, "dist-tags", "versions", "time", "maintainers", "description", "repository", "homepage", "--json"])
  (out/"meta.json").write_text(mv.stdout, encoding="utf-8")
  pk = run(["npm", "pack", pkg]); (out/"pack.out").write_text(pk.stdout+pk.stderr, encoding="utf-8")
  tgz = None
  for line in (pk.stdout+pk.stderr).splitlines():
    if line.strip().endswith(".tgz") and Path(line.strip()).exists():
      tgz = Path(line.strip())
  if tgz:
    dest = out/tgz.name; tgz.rename(dest)
    (out/"sha256.txt").write_text(sha256sum(dest)+"  "+dest.name+"\n", encoding="utf-8")
    ext = out/"extracted"; ext.mkdir(exist_ok=True)
    with tarfile.open(dest, "r:gz") as tf: tf.extractall(ext)
    hits = []
    for p in ext.rglob("*"):
      if p.is_file():
        try: txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception: continue
        for rx in REGEXES:
          for m in re.finditer(rx, txt):
            hits.append({"file": str(p.relative_to(ext)), "pattern": rx, "start": m.start()})
    (out/"grep_hits.json").write_text(json.dumps(hits, indent=2), encoding="utf-8")
  bin_path = os.environ.get("TYPOSENTINEL_BIN", "typosentinel")
  ts = run([bin_path, "scan", "--ecosystem", "npm", "--package", pkg, "--format", "json", "--policy", "paranoid"])
  (out/"typosentinel.json").write_text(ts.stdout, encoding="utf-8")
  print(f"Done. See {out}")
if __name__ == "__main__": main()
