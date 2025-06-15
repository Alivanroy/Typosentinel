import json, subprocess, pathlib

FIXTURE = pathlib.Path(__file__).parent/"fixtures"/"deep_tree.tgz"

def test_deep_dependencies():
    report = json.loads(subprocess.check_output(["go", "run", "./cmd/scanner", "scan", str(FIXTURE)]))
    nested = report["summary"]["dependency_depth"]
    assert nested >= 10