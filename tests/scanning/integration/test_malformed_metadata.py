import subprocess, pathlib, json
BAD = pathlib.Path(__file__).parent/"fixtures"/"bad_meta.tgz"

def test_bad_metadata():
    out = subprocess.check_output(["go", "run", "./cmd/scanner", "scan", str(BAD)])
    report = json.loads(out)
    assert report["status"] in ("clean", "malicious")  # should not crash