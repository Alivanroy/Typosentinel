import subprocess, json, pathlib

FIXTURE = pathlib.Path(__file__).parent/"fixtures"/"apt_pkg.tgz"

def test_apt_chain():
    report = json.loads(subprocess.check_output(["go", "run", "./cmd/scanner", "scan", str(FIXTURE)]))
    assert report["flags"].count("multi_stage") > 0