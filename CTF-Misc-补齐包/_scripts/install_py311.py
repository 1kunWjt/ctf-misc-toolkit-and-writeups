# -*- coding: utf-8 -*-
"""为 binwalk v2 配一个独立的 Python 3.11 嵌入式运行时（3.12+ 已删除 imp 模块）。"""
import io
import os
import ssl
import sys
import urllib.request
import zipfile

ROOT = r"D:\XiaoMibook\CTF学习\CTF-Misc-补齐包"
BW = os.path.join(ROOT, r"04-文件与十六进制\binwalk")
PY_DIR = os.path.join(BW, "python311")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

URLS = [
    "https://mirrors.huaweicloud.com/python/3.11.9/python-3.11.9-embed-amd64.zip",
    "https://registry.npmmirror.com/-/binary/python/3.11.9/python-3.11.9-embed-amd64.zip",
    "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip",
]


def fetch():
    for u in URLS:
        try:
            raw = urllib.request.urlopen(
                urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"}),
                timeout=120, context=CTX).read()
            if len(raw) < 5 * 1024 * 1024:
                print("  太小，跳过:", u)
                continue
            print("OK %.2f MB <- %s" % (len(raw) / 1048576, u))
            return raw
        except Exception as e:
            print("  失败 %s: %s" % (u, type(e).__name__))
    return None


def main():
    os.makedirs(PY_DIR, exist_ok=True)
    if not os.path.exists(os.path.join(PY_DIR, "python.exe")):
        raw = fetch()
        if not raw:
            print("全部下载失败")
            return 1
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            z.extractall(PY_DIR)

    # 把 binwalk 源码目录写进 ._pth（嵌入式 Python 只认这个）
    pth = None
    for f in os.listdir(PY_DIR):
        if f.endswith("._pth"):
            pth = os.path.join(PY_DIR, f)
    if pth:
        want = r"..\lib\src"
        with open(pth, "r+", encoding="utf-8") as f:
            content = f.read()
            if want not in content:
                content = content.replace("#import site", "import site")
                if not content.endswith("\n"):
                    content += "\n"
                content += want + "\n"
                f.seek(0)
                f.write(content)
        print("已更新", pth)
    print("python:", os.path.join(PY_DIR, "python.exe"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
