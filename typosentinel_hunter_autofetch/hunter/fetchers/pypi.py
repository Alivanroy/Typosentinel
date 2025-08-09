
from ..util import http_get, parse_rss_titles
from typing import List, Dict, Any

SEARCH_URL = "https://pypi.org/pypi/{name}/json"
RSS_NEW = "https://pypi.org/rss/packages.xml"

def fetch_recent_pypi(names: List[str]) -> List[Dict[str, Any]]:
    items = []
    for n in names:
        r = http_get(SEARCH_URL.format(name=n))
        if not r:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        info = data.get("info", {})
        releases = data.get("releases", {})
        latest_version = info.get("version")
        latest_time = None
        if latest_version and releases.get(latest_version):
            files = releases.get(latest_version, [])
            if files:
                latest_time = files[-1].get("upload_time_iso_8601")
        items.append({
            "ecosystem": "pypi",
            "name": n,
            "version": latest_version,
            "updated": latest_time,
            "summary": info.get("summary"),
            "homepage": info.get("home_page"),
        })
    return items

def fetch_pypi_auto(limit: int = 20) -> List[Dict[str, Any]]:
    r = http_get(RSS_NEW)
    names: List[str] = []
    if r and r.status_code == 200:
        titles = parse_rss_titles(r.text)
        # Extract package names from titles like "package-name added to PyPI"
        for title in titles:
            if " added to PyPI" in title:
                package_name = title.replace(" added to PyPI", "").strip()
                names.append(package_name)
            else:
                # Fallback: use the title as-is
                names.append(title.strip())
        names = names[:limit]
        print(f"      📋 Extracted {len(names)} package names: {names[:5]}...")
    return fetch_recent_pypi(names)
