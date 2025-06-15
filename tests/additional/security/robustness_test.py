import requests

def test_network_partition():
    try:
        requests.post("http://api:8080/scan", timeout=2)
    except requests.exceptions.ReadTimeout:
        pass  # acceptable