import base64, pytest, requests, textwrap

API = "http://ml:8000/analyse/code"

obfuscated = textwrap.dedent("""
    import base64, os
    exec(base64.b64decode(b'aW1wb3J0IHN5cywgb3M7IHByaW50KCdldmlsJyk='))
""")

@pytest.mark.parametrize("snippet, expected", [
    (obfuscated, True),
    ("print('benign')", False),
])

def test_obfuscation(snippet, expected):
    r = requests.post(API, json={"code": snippet})
    r.raise_for_status()
    assert r.json()["malicious"] == expected