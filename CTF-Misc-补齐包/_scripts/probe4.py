# -*- coding: utf-8 -*-
"""Fourth probe: binaries committed inside repos + sourceforge mirrors."""
import json
import urllib.request

GH = {"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github+json"}


def api(url):
    return json.loads(urllib.request.urlopen(
        urllib.request.Request(url, headers=GH), timeout=30).read().decode("utf-8", "replace"))


def head(url, ua="Mozilla/5.0"):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=30) as r:
            cl = r.headers.get("Content-Length")
            return "OK %s %s" % (r.status, round(int(cl) / 1048576, 2) if cl else "?")
    except Exception as e:
        return "FAIL %s %s" % (type(e).__name__, str(e)[:70])


print("### 直链 ###")
for n, u in [
    ("tweakpng-1.4.9", "https://entropymine.com/jason/tweakpng/tweakpng-1.4.9.zip"),
    ("yafu-dl-mirror", "https://downloads.sourceforge.net/project/yafu/1.34/yafu-1.34.zip"),
    ("yafu-dl-mirror2", "https://master.dl.sourceforge.net/project/yafu/1.34/yafu-1.34-win32.zip"),
    ("zipcenop-jar", "https://github.com/442048209as/ZipCenOp/raw/master/ZipCenOp.jar"),
    ("stegseek-win", "https://github.com/RickdeJager/stegseek/releases/latest"),
]:
    print("%-20s %s" % (n, head(u)))

print()
print("### 仓库文件树里找 exe/jar ###")
for repo in ["442048209as/ZipCenOp", "Byxs20/PuzzleSolver", "AabyssZG/CRC32-Tools",
             "AabyssZG/Deformed-Image-Restorer", "AabyssZG/FileReverse-Tools",
             "Tokeii0/VolatilityPro", "Charleswyt/MP3Stego", "fabienpe/MP3Stego",
             "itsprogrammernotcoder/stegdetect", "BionicSwash/Stegdetect",
             "merricx/qrazybox", "chishaxie/BlindWaterMark"]:
    try:
        meta = api(f"https://api.github.com/repos/{repo}")
        br = meta["default_branch"]
        tree = api(f"https://api.github.com/repos/{repo}/git/trees/{br}?recursive=1")
        hits = [t["path"] for t in tree.get("tree", [])
                if t["path"].lower().endswith((".exe", ".jar", ".zip", ".whl", ".msi"))]
        print("%-38s branch=%-8s 命中: %s" % (repo, br, hits[:8] if hits else "无"))
    except Exception as e:
        print("%-38s !! %s %s" % (repo, type(e).__name__, str(e)[:60]))
