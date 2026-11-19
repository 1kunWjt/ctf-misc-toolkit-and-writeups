# -*- coding: utf-8 -*-
"""
下载 CTF 杂项补齐包所需的安装文件。
- GitHub 走 ghfast.top 加速（直链在国内基本卡死）
- PyPI 走清华源
用法: python download_all.py [--only 关键字]
"""
import os
import ssl
import sys
import time
import urllib.request

ROOT = r"D:\XiaoMibook\CTF学习\CTF-Misc-补齐包"
CACHE = os.path.join(ROOT, "_下载")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

HDRS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
GHFAST = "https://ghfast.top/"

# (名称, 保存文件名, URL)
ITEMS = [
    # ---------- 隐写 ----------
    ("StegSolve", "StegSolve-1.4.jar",
     GHFAST + "https://github.com/Giotino/stegsolve/releases/download/v1.4/StegSolve-1.4.jar"),
    ("TweakPNG", "tweakpng-1.4.6.zip",
     "https://entropymine.com/jason/tweakpng/tweakpng-1.4.6.zip"),
    ("QrazyBox", "qrazybox-master.zip",
     GHFAST + "https://github.com/merricx/qrazybox/archive/refs/heads/master.zip"),
    ("BlindWaterMark-python", "BlindWaterMark-master.zip",
     GHFAST + "https://github.com/chishaxie/BlindWaterMark/archive/refs/heads/master.zip"),
    ("ruby-便携(for zsteg)", "rubyinstaller-3.4.7-1-x64.7z",
     GHFAST + "https://github.com/oneclick/rubyinstaller2/releases/download/RubyInstaller-3.4.7-1/rubyinstaller-3.4.7-1-x64.7z"),

    # ---------- 取证 ----------
    ("MemProcFS", "MemProcFS-win_x64-v5.19.1.zip",
     GHFAST + "https://github.com/ufrisk/MemProcFS/releases/download/v5.19/"
              "MemProcFS_files_and_binaries_v5.19.1-win_x64-20261102.zip"),
    ("LovelyMem", "Lovelymem-V2-2.5.0-windows-x64.exe",
     GHFAST + "https://github.com/Tokeii0/LovelyMem/releases/download/v2.5.0/"
              "Lovelymem-V2-2.5.0-windows-x64.exe"),
    ("Hashcat", "hashcat-8.0.0.7z",
     GHFAST + "https://github.com/hashcat/hashcat/releases/download/v8.0.0/hashcat-8.0.0.7z"),
    ("ZipCenOp", "ZipCenOp-master.zip",
     GHFAST + "https://github.com/442048209as/ZipCenOp/archive/refs/heads/master.zip"),

    # ---------- MISC 解题 ----------
    ("PuzzleSolver", "PuzzleSolver-main.zip",
     GHFAST + "https://github.com/Byxs20/PuzzleSolver/archive/refs/heads/main.zip"),
    ("CRC32-Tools", "CRC32-Tools-main.zip",
     GHFAST + "https://github.com/AabyssZG/CRC32-Tools/archive/refs/heads/main.zip"),
    ("FileReverse-Tools", "FileReverse-Tools-main.zip",
     GHFAST + "https://github.com/AabyssZG/FileReverse-Tools/archive/refs/heads/main.zip"),
    ("FileReverse-Tools-exe", "FileReverse-Tools_Win_x64_1.02.exe",
     GHFAST + "https://github.com/AabyssZG/FileReverse-Tools/releases/download/1.02/"
              "FileReverse-Tools_Win_x64_1.02.exe"),
    ("PNG尺寸修复", "Deformed-Image-Restorer-main.zip",
     GHFAST + "https://github.com/AabyssZG/Deformed-Image-Restorer/archive/refs/heads/main.zip"),
    ("Typhon", "typhonbreaker-1.0.13.9-py3-none-any.whl",
     GHFAST + "https://github.com/LamentXU123/Typhon/releases/download/v1.0.13/"
              "typhonbreaker-1.0.13.9-py3-none-any.whl"),
    ("CTFCrackTools", "ctfcracktools-x-0.1.2-windows-x64.exe",
     GHFAST + "https://github.com/0Chencc/CTFCrackTools/releases/download/v0.1.2/"
              "ctfcracktools-x-0.1.2-windows-x64.exe"),
    ("Ciphey", "ciphey-windows-x86_64.zip",
     GHFAST + "https://github.com/Ciphey/Ciphey/releases/download/v0.12.1/"
              "ciphey-windows-x86_64.zip"),

    # ---------- 文件处理 / pip 源包 ----------
    ("binwalk-sdist", "binwalk-2.3.4.tar.gz",
     "https://pypi.tuna.tsinghua.edu.cn/packages/source/b/binwalk/binwalk-2.3.4.tar.gz"),
]


def already(path):
    return os.path.exists(path) and os.path.getsize(path) > 512


def download(url, path, tries=4):
    tmp = path + ".part"
    err = ""
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=HDRS)
            with urllib.request.urlopen(req, timeout=45, context=CTX) as r:
                done = 0
                with open(tmp, "wb") as f:
                    while True:
                        chunk = r.read(131072)
                        if not chunk:
                            break
                        f.write(chunk)
                        done += len(chunk)
                # 有些代理会返回 HTML 错误页
                if done < 512:
                    raise RuntimeError("响应过小(%d B)，可能是代理错误页" % done)
            os.replace(tmp, path)
            return True, done
        except Exception as e:
            err = "%s: %s" % (type(e).__name__, str(e)[:110])
            time.sleep(1.0 * (i + 1))
    if os.path.exists(tmp):
        try:
            os.remove(tmp)
        except OSError:
            pass
    return False, err


def main():
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1].lower()
    os.makedirs(CACHE, exist_ok=True)
    ok = fail = skip = 0
    failed = []
    for name, fn, url in ITEMS:
        if only and only not in name.lower() and only not in fn.lower():
            continue
        path = os.path.join(CACHE, fn)
        if already(path):
            skip += 1
            print("[SKIP] %-26s %s" % (name, fn), flush=True)
            continue
        t0 = time.time()
        good, info = download(url, path)
        if good:
            ok += 1
            print("[OK]   %-26s %8.2f MB %6.1fs" % (name, info / 1048576, time.time() - t0),
                  flush=True)
        else:
            fail += 1
            failed.append((name, info))
            print("[FAIL] %-26s %s" % (name, info), flush=True)
    print("\n== 下载汇总: 成功 %d / 跳过 %d / 失败 %d ==" % (ok, skip, fail), flush=True)
    for n, e in failed:
        print("   FAIL", n, "|", e, flush=True)


if __name__ == "__main__":
    main()
