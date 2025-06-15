import subprocess, pathlib, json, pytest
BOMB = pathlib.Path(__file__).parent/"fixtures"/"zip_bomb.zip"

@pytest.mark.timeout(45)
def test_zip_bomb():
    out = subprocess.check_output(["go", "run", "./cmd/scanner", "scan", str(BOMB)])
    assert b"ArchiveBombError" in out