
from ..util import http_get
from typing import List, Dict, Any
import json

GO_LIST = "https://index.golang.org/index"  # returns stream; we'll take the first N lines
GO_VERSIONS = "https://proxy.golang.org/{module}/@v/list"

def fetch_go_meta(modules: List[str]) -> List[Dict[str, Any]]:
    items = []
    print(f"      📋 Fetching metadata for {len(modules)} Go modules...")
    for i, m in enumerate(modules):
        print(f"      📦 [{i+1}/{len(modules)}] Fetching versions for {m}")
        url = GO_VERSIONS.format(module=m)
        r = http_get(url)
        if not r or r.status_code != 200:
            print(f"      ⚠️ Failed to get versions for {m}")
            continue
        versions = [v.strip() for v in r.text.strip().splitlines() if v.strip()]
        latest = versions[-1] if versions else None
        print(f"      ✅ {m}: latest version {latest}")
        items.append({
            "ecosystem": "go",
            "name": m,
            "version": latest,
            "updated": None,
            "summary": "",
            "homepage": "",
        })
    return items

def fetch_go_auto(limit: int = 10) -> List[Dict[str, Any]]:
    print(f"      🔍 Fetching Go module index...")
    r = http_get(GO_LIST)
    modules: List[str] = []
    
    if r and r.status_code == 200:
        print(f"      📄 Processing Go module index data...")
        lines_processed = 0
        for line in r.text.strip().splitlines()[:limit*3]:
            lines_processed += 1
            # Each line like: {"Path":"<module>","Timestamp":"...","Version":"..."}
            line = line.strip().strip(",")
            if not line:
                continue
            
            try:
                # Try proper JSON parsing first
                data = json.loads(line)
                mod = data.get("Path")
                if mod and mod not in modules:
                    modules.append(mod)
            except json.JSONDecodeError:
                # Fallback to string parsing
                start = line.find('"Path"')
                if start != -1:
                    colon = line.find(":", start)
                    if colon != -1:
                        q1 = line.find('"', colon+1)
                        q2 = line.find('"', q1+1)
                        if q1 != -1 and q2 != -1:
                            mod = line[q1+1:q2]
                            if mod and mod not in modules:
                                modules.append(mod)
            
            if len(modules) >= limit:
                break
        
        print(f"      📋 Processed {lines_processed} lines, found {len(modules)} unique modules: {modules[:3]}...")
    else:
        print(f"      ❌ Failed to fetch Go module index")
        # Fallback to some popular Go modules
        modules = ["github.com/gin-gonic/gin", "github.com/gorilla/mux", "github.com/sirupsen/logrus", 
                  "github.com/stretchr/testify", "github.com/spf13/cobra"][:limit]
        print(f"      ⚠️ Using fallback Go modules: {modules}")
    
    return fetch_go_meta(modules[:limit])
