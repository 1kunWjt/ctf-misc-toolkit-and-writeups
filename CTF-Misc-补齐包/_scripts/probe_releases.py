# -*- coding: utf-8 -*-
"""Probe GitHub latest releases to find Windows-friendly assets."""
import json
import urllib.request

REPOS = [
    "ReFirmLabs/binwalk",
    "WerWolv/ImHex",
    "Giotino/stegsolve",
    "merricx/qrazybox",
    "ww23/BlindWatermark",
    "chishaxie/BlindWaterMark",
    "abeluck/stegdetect",
    "442048209as/ZipCenOp",
    "hashcat/hashcat",
    "openwall/john",
    "ufrisk/MemProcFS",
    "Byxs20/PuzzleSolver",
    "LamentXU123/Typhon",
    "AabyssZG/Deformed-Image-Restorer",
    "AabyssZG/FileReverse-Tools",
    "AabyssZG/CRC32-Tools",
    "Tokeii0/LovelyMem",
    "Tokeii0/VolatilityPro",
    "0Chencc/CTFCrackTools",
    "bannsec/stegoVeritas",
    "Ciphey/Ciphey",
]

HDRS = {"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github+json"}


def get(url):
    req = urllib.request.Request(url, headers=HDRS)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


for repo in REPOS:
    print("=" * 70)
    print(repo)
    try:
        d = get(f"https://api.github.com/repos/{repo}/releases/latest")
    except Exception as e:
        print("  !! latest error:", type(e).__name__, e)
        d = None
    if d:
        print("  tag:", d.get("tag_name"))
        for a in d.get("assets", []):
            print("   - %-55s %9.2f MB" % (a["name"], a["size"] / 1048576))
        if not d.get("assets"):
            print("   (no assets)")
