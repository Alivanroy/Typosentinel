
# Typosentinel Hunter (discover new CVE candidates)

This tool polls or accepts lists of **npm/PyPI/Go** packages, scans them with **Typosentinel**,
and flags **high-risk candidates** that may warrant **CVE reporting**.

## Usage
```bash
pip install requests
export TYPOSENTINEL_BIN=/usr/local/bin/typosentinel

# Seed with your own lists (ideally pulled from registry feeds)
python3 hunt.py --ecosystems pypi,npm,go   --pypi-names reqeusts,pandasx   --npm-names expressz,lodashh   --go-modules example.com/corp/internal-utils   --policy paranoid
```

Outputs:
- `out/all_scans.json` — every scan result
- `out/candidates.json` — items that matched candidate rules

> Wire this with a registry listener to feed in **brand-new** package names to maximize discovery chance.
> Always follow responsible disclosure practices (see `disclosure/REPORT_TEMPLATE.md`).

