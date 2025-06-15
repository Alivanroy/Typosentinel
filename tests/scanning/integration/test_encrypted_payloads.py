import subprocess, pathlib, json
CRYPT = pathlib.Path(__file__).parent/"fixtures"/"encrypted.tgz"

def test_encrypted_payload():
    out = subprocess.check_output(["go", "run", "./cmd/scanner", "scan", str(CRYPT)])
    report = json.loads(out)
    assert report["flags"].count("encrypted_content") == 1