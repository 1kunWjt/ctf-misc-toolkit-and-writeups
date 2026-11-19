# -*- coding: utf-8 -*-
"""把 _下载 里的压缩包解到各工具目录（zip / 7z / tar.gz），并去掉多余的一层壳目录。"""
import os
import shutil
import subprocess
import tarfile
import zipfile

ROOT = r"D:\XiaoMibook\CTF学习\CTF-Misc-补齐包"
CACHE = os.path.join(ROOT, "_下载")
BZ = r"C:\Program Files\Bandizip\bz.exe"

ZIP_MAP = {
    "tweakpng-1.4.6.zip": r"01-隐写工具\TweakPNG",
    "qrazybox-master.zip": r"01-隐写工具\QrazyBox",
    "BlindWaterMark-master.zip": r"01-隐写工具\BlindWaterMark-Python",
    "MemProcFS-win_x64-v5.19.1.zip": r"02-取证工具\MemProcFS",
    "ZipCenOp-master.zip": r"02-取证工具\ZipCenOp",
    "PuzzleSolver-main.zip": r"03-MISC解题\PuzzleSolver",
    "CRC32-Tools-main.zip": r"03-MISC解题\CRC32-Tools",
    "FileReverse-Tools-main.zip": r"03-MISC解题\FileReverse-Tools",
    "Deformed-Image-Restorer-main.zip": r"03-MISC解题\PNG尺寸修复",
    "ciphey-windows-x86_64.zip": r"03-MISC解题\Ciphey",
}
SEVEN_ZIP_MAP = {
    "hashcat-8.0.0.7z": r"02-取证工具\Hashcat",
    "rubyinstaller-3.4.7-1-x64.7z": r"01-隐写工具\zsteg\ruby",
}
TAR_MAP = {}
SINGLE_FILES = {
    "StegSolve-1.4.jar": r"01-隐写工具\StegSolve",
    "Lovelymem-V2-2.5.0-windows-x64.exe": r"02-取证工具\LovelyMem",
    "ctfcracktools-x-0.1.2-windows-x64.exe": r"03-MISC解题\CTFCrackTools",
    "FileReverse-Tools_Win_x64_1.02.exe": r"03-MISC解题\FileReverse-Tools",
    "typhonbreaker-1.0.13.9-py3-none-any.whl": r"03-MISC解题\Typhon",
}


def flatten(path, keep=()):
    try:
        items = [i for i in os.listdir(path) if i not in keep]
    except OSError:
        return
    if len(items) == 1:
        only = os.path.join(path, items[0])
        if os.path.isdir(only):
            for name in os.listdir(only):
                shutil.move(os.path.join(only, name), os.path.join(path, name))
            os.rmdir(only)


def unzip(src, dst):
    with zipfile.ZipFile(src) as z:
        bad = z.testzip()
        if bad:
            raise RuntimeError("zip 损坏: " + bad)
        z.extractall(dst)


def sevenzip(src, dst):
    p = subprocess.run([BZ, "x", "-y", "-o:" + dst, src],
                       capture_output=True, text=True)
    if p.returncode != 0 or not os.listdir(dst):
        raise RuntimeError("bz.exe 解压失败 rc=%s %s" % (p.returncode, (p.stderr or "")[-200:]))


def untar(src, dst):
    with tarfile.open(src, "r:gz") as t:
        t.extractall(dst)


def do_map(mapping, func, label, log):
    for fn, rel in mapping.items():
        src = os.path.join(CACHE, fn)
        dst = os.path.join(ROOT, rel)
        if not os.path.exists(src):
            log.append((label, fn, "源文件缺失"))
            continue
        os.makedirs(dst, exist_ok=True)
        if os.listdir(dst):
            log.append((label, fn, "已解压，跳过"))
            continue
        try:
            func(src, dst)
            flat = dst
            if "zsteg" in rel:
                flat_keep = set()
            else:
                flat_keep = set()
            flatten(flat, flat_keep)
            log.append((label, fn, "OK"))
        except Exception as e:
            log.append((label, fn, "FAIL %s" % e))


def main():
    log = []
    do_map(ZIP_MAP, unzip, "zip", log)
    do_map(SEVEN_ZIP_MAP, sevenzip, "7z", log)
    do_map(TAR_MAP, untar, "tar", log)
    for fn, rel in SINGLE_FILES.items():
        src = os.path.join(CACHE, fn)
        dst = os.path.join(ROOT, rel)
        if not os.path.exists(src):
            log.append(("file", fn, "源文件缺失"))
            continue
        os.makedirs(dst, exist_ok=True)
        try:
            shutil.copy2(src, os.path.join(dst, fn))
            log.append(("file", fn, "OK"))
        except Exception as e:
            log.append(("file", fn, "FAIL %s" % e))

    print("%-6s %-52s %s" % ("类型", "文件", "结果"))
    for t, fn, st in log:
        print("%-6s %-52s %s" % (t, fn, st))


if __name__ == "__main__":
    main()
