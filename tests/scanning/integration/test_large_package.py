import subprocess, json, pathlib
LARGE = pathlib.Path(__file__).parent/"fixtures"/"large_pkg.tgz"

def test_large():
    report = json.loads(subprocess.check_output(["go", "run", "./cmd/scanner", "scan", str(LARGE)]))
    assert report["duration_ms"] < 5*60*1000