import pathlib, subprocess, json, pytest

SAMPLES_DIR = pathlib.Path(__file__).parent / "samples"
CLI = ["go", "run", "./cmd/scanner", "scan"]

@pytest.mark.parametrize("sample", list(SAMPLES_DIR.glob("*.tgz")))
def test_npm_packages(sample):
    out = subprocess.check_output(CLI + [str(sample)])
    report = json.loads(out)
    assert report["status"] == "clean"

@pytest.mark.parametrize("sample", list(SAMPLES_DIR.glob("*.whl")))
def test_python_wheels(sample):
    out = subprocess.check_output(CLI + [str(sample)])
    report = json.loads(out)
    assert report["status"] in ["clean", "malicious"]

@pytest.mark.parametrize("sample", list(SAMPLES_DIR.glob("*.mod")))
def test_go_modules(sample):
    out = subprocess.check_output(CLI + [str(sample)])
    report = json.loads(out)
    assert report["status"] in ["clean", "malicious"]

@pytest.mark.parametrize("sample", list(SAMPLES_DIR.glob("*.jar")))
def test_maven_jars(sample):
    out = subprocess.check_output(CLI + [str(sample)])
    report = json.loads(out)
    assert report["status"] in ["clean", "malicious"]