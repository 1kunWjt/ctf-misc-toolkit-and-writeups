# -*- coding: utf-8 -*-
"""Third probe: direct vendor URLs + extra repos."""
import json
import urllib.request

HDRS = {"User-Agent": "Mozilla/5.0"}
GH = {"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github+json"}


def head(url):
    try:
        req = urllib.request.Request(url, headers=HDRS, method="GET")
        with urllib.request.urlopen(req, timeout=30) as r:
            cl = r.headers.get("Content-Length")
            return "OK  %s  %s MB" % (r.status,
                                      round(int(cl) / 1048576, 2) if cl else "?")
    except Exception as e:
        return "FAIL %s %s" % (type(e).__name__, str(e)[:90])


URLS = [
    ("john-jumbo-win64", "https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip"),
    ("yafu-sourceforge", "https://sourceforge.net/projects/yafu/files/latest/download"),
    ("yafu-direct", "https://sourceforge.net/projects/yafu/files/yafu-1.34/yafu-1.34-win32.zip/download"),
    ("ntfsstreams-nirsoft", "https://www.nirsoft.net/utils/ntfsstreamseditor.zip"),
    ("tweakpng-site", "https://entropymine.com/jason/tweakpng/tweakpng-1.4.6.zip"),
    ("mp3stego-site", "https://www.petitcolas.net/fabien/steganography/mp3stego/mp3stego-v0.7-win32.zip"),
    ("rubyinstaller-7z", "https://github.com/oneclick/rubyinstaller2/releases/download/RubyInstaller-3.4.7-1/rubyinstaller-3.4.7-1-x64.7z"),
    ("bulk_extractor-win", "https://github.com/simsong/bulk_extractor/releases"),
    ("photorec-win", "https://www.cgsecurity.org/testdisk-7.2-WIP.win64.zip"),
]

for name, u in URLS:
    print("%-22s %s" % (name, head(u)))

print()
print("### extra repos (release assets) ###")
for repo in ["jsummers/tweakpng", "fabienpe/MP3Stego", "poizan42/stegdetect",
             "itsprogrammernotcoder/stegdetect", "oneclick/rubyinstaller2"]:
    try:
        d = json.loads(urllib.request.urlopen(
            urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest",
                                   headers=GH), timeout=30).read().decode())
        print(repo, "tag=", d.get("tag_name"))
        for a in d.get("assets", []):
            print("   - %-58s %8.2f MB" % (a["name"], a["size"] / 1048576))
    except Exception as e:
        print(repo, "!!", type(e).__name__, str(e)[:80])
