
from ..util import http_get
from typing import List, Dict, Any

NPM_META = "https://registry.npmjs.org/{name}"
# Use search API sorted by updated; using text='*' and weights to broaden results
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"

def fetch_npm_meta(names: List[str]) -> List[Dict[str, Any]]:
    items = []
    for n in names:
        r = http_get(NPM_META.format(name=n))
        if not r:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        dist_tags = data.get("dist-tags", {})
        latest = dist_tags.get("latest")
        time_obj = data.get("time", {})
        latest_time = time_obj.get(latest) if isinstance(time_obj, dict) else None
        items.append({
            "ecosystem": "npm",
            "name": n,
            "version": latest,
            "updated": latest_time,
            "summary": (data.get("description") or "")[:200],
            "homepage": data.get("homepage"),
        })
    return items

def fetch_npm_auto(limit: int = 20) -> List[Dict[str, Any]]:
    print(f"      🔍 Fetching latest npm packages...")
    
    # Use simple search parameters that work with npm registry API
    # Based on official documentation: text, size, from, quality, popularity, maintenance
    search_params = {
        "text": "react",  # Start with a popular search term
        "size": limit * 2,
        "from": 0,
        "popularity": 1.0,  # Prioritize popular packages
        "quality": 0.5,
        "maintenance": 0.5
    }
    
    names: List[str] = []
    
    print(f"      🔍 npm search with params: {search_params}")
    r = http_get(NPM_SEARCH, params=search_params)
    
    if r and r.status_code == 200:
        try:
            data = r.json()
            objects = data.get("objects", [])
            print(f"      ✅ Found {len(objects)} packages in search results")
            
            for obj in objects[:limit]:
                pkg = obj.get("package", {})
                name = pkg.get("name")
                if name and name not in names:
                    names.append(name)
                    print(f"      📦 Added: {name}")
            
        except Exception as e:
            print(f"      ❌ Error parsing search results: {e}")
    else:
        print(f"      ❌ Search failed with status: {r.status_code if r else 'No response'}")
    
    # If we don't have enough packages, try a broader search
    if len(names) < limit:
        print(f"      🔍 Trying broader search for more packages...")
        broader_params = {
            "text": "javascript",
            "size": limit * 2,
            "from": 0,
            "popularity": 0.8,
            "quality": 0.6,
            "maintenance": 0.6
        }
        
        r2 = http_get(NPM_SEARCH, params=broader_params)
        if r2 and r2.status_code == 200:
            try:
                data2 = r2.json()
                objects2 = data2.get("objects", [])
                print(f"      ✅ Found {len(objects2)} additional packages")
                
                for obj in objects2:
                    if len(names) >= limit:
                        break
                    pkg = obj.get("package", {})
                    name = pkg.get("name")
                    if name and name not in names:
                        names.append(name)
                        print(f"      📦 Added: {name}")
                        
            except Exception as e:
                print(f"      ❌ Error parsing broader search results: {e}")
    
    if not names:
        print(f"      ⚠️ All npm search attempts failed, using fallback package list")
        # Fallback to some popular packages for testing
        names = ["express", "lodash", "react", "vue", "angular", "webpack", "babel", "eslint", "prettier", "typescript"][:limit]
    
    return fetch_npm_meta(names[:limit])
