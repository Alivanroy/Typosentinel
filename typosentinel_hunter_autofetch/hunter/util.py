
import time, random, requests

DEFAULT_TIMEOUT = 20

def backoff_sleep(retry):
    time.sleep(min(30, (2 ** retry) + random.random()))

def http_get(url, params=None, headers=None, timeout=DEFAULT_TIMEOUT, retries=3):
    print(f"      🌐 HTTP GET: {url}")
    for i in range(retries+1):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=timeout)
            print(f"      📡 Response: {r.status_code}")
            if r.status_code == 200:
                return r
        except Exception as e:
            print(f"      ❌ HTTP error (attempt {i+1}/{retries+1}): {str(e)}")
        if i < retries:
            print(f"      ⏳ Retrying in {min(30, (2 ** i) + random.random()):.1f}s...")
            backoff_sleep(i)
    print(f"      💥 Failed after {retries+1} attempts")
    return None


from xml.etree import ElementTree as ET

def parse_rss_titles(xml_text: str):
    titles = []
    try:
        root = ET.fromstring(xml_text)
        # RSS: channel/item/title
        for item in root.findall(".//item"):
            title = item.findtext("title")
            if title:
                titles.append(title.strip())
        # Atom: entry/title
        for entry in root.findall(".//{http://www.w3.org/2005/Atom}entry"):
            t = entry.findtext("{http://www.w3.org/2005/Atom}title")
            if t:
                titles.append(t.strip())
    except Exception:
        pass
    # dedupe preserve order
    seen = set()
    out = []
    for t in titles:
        if t not in seen:
            seen.add(t); out.append(t)
    return out
