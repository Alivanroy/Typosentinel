import requests, pytest

@pytest.mark.parametrize("payload", [
    {"username":"admin' OR '1'='1","password":"x"},
    {"token":"../../../../etc/passwd"},
])

def test_auth_bypass(payload):
    r = requests.post("http://api:8080/login", json=payload)
    assert r.status_code == 401