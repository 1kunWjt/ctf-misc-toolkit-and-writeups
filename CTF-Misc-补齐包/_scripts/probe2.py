# -*- coding: utf-8 -*-
"""Second probe: repos without releases, direct-vendor URLs, and GitHub search."""
import json
import urllib.request

HDRS = {"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github+json"}


def get(url):
    req = urllib.request.Request(url, headers=HDRS)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


print("### repo meta ###")
for repo in [
    "merricx/qrazybox", "chishaxie/BlindWaterMark", "442048209as/ZipCenOp",
    "Tokeii0/VolatilityPro", "AabyssZG/CRC32-Tools", "AabyssZG/FileReverse-Tools",
    "AabyssZG/Deformed-Image-Restorer", "Byxs20/PuzzleSolver", "bannsec/stegoVeritas",
    "EricZimmerman/RegistryExplorer", "slimm609/checksec.sh",
]:
    try:
        d = get(f"https://api.github.com/repos/{repo}")
        print("%-42s default=%-12s stars=%-6s pushed=%s" % (
            repo, d.get("default_branch"), d.get("stargazers_count"),
            str(d.get("pushed_at"))[:10]))
    except Exception as e:
        print("%-42s !! %s %s" % (repo, type(e).__name__, e))

print()
print("### releases list (first tag + asset count) ###")
for repo in ["Tokeii0/VolatilityPro", "bannsec/stegoVeritas", "442048209as/ZipCenOp",
             "AabyssZG/CRC32-Tools", "AabyssZG/FileReverse-Tools",
             "AabyssZG/Deformed-Image-Restorer", "Byxs20/PuzzleSolver"]:
    try:
        rels = get(f"https://api.github.com/repos/{repo}/releases?per_page=3")
        for r in rels:
            print("%-40s tag=%-10s assets=%s" % (repo, r.get("tag_name"),
                                                 [a["name"] for a in r.get("assets", [])]))
        if not rels:
            print("%-40s (no releases)" % repo)
    except Exception as e:
        print("%-40s !! %s" % (repo, e))

print()
print("### github search: steghide / foremost / tweakpng / stegdetect / mp3stego ###")
for q in ["steghide+windows+in:name", "foremost+windows+in:name", "tweakpng",
          "stegdetect", "mp3stego", "ZipCenOp"]:
    try:
        d = get(f"https://api.github.com/search/repositories?q={q}&per_page=5")
        print("--", q)
        for it in d.get("items", []):
            print("   %-45s stars=%-5s %s" % (it["full_name"], it["stargazers_count"],
                                              (it["description"] or "")[:60]))
    except Exception as e:
        print("--", q, "!!", e)
