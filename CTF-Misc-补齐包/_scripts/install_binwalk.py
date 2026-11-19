# -*- coding: utf-8 -*-
"""手动装 binwalk（PyPI 只有 sdist，且沙箱里 pip 的构建隔离建临时目录会失败）：
直接下 sdist 解压到 lib 目录，再加个启动入口。"""
import io
import json
import os
import ssl
import tarfile
import urllib.request

ROOT = r"D:\XiaoMibook\CTF学习\CTF-Misc-补齐包"
LIB = os.path.join(ROOT, r"04-文件与十六进制\binwalk\lib")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "pip/26.1.2"}


def main():
    meta = json.loads(urllib.request.urlopen(
        urllib.request.Request("https://pypi.org/pypi/binwalk/json", headers=UA),
        timeout=30, context=CTX).read().decode())
    ver = meta["info"]["version"]
    url = None
    for f in meta["releases"][ver]:
        if f["packagetype"] == "sdist":
            url = f["url"]
            break
    print("binwalk", ver, url)
    raw = urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                 timeout=60, context=CTX).read()
    print("downloaded %.2f MB" % (len(raw) / 1048576))
    os.makedirs(LIB, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as t:
        t.extractall(LIB)
    top = [d for d in os.listdir(LIB) if os.path.isdir(os.path.join(LIB, d))]
    print("解压出:", top)
    # 把顶层目录里的内容提上来，方便 PYTHONPATH 指向
    for d in top:
        src = os.path.join(LIB, d)
        for name in os.listdir(src):
            os.replace(os.path.join(src, name), os.path.join(LIB, name))
        os.rmdir(src)
    print("lib 目录内容:", sorted(os.listdir(LIB))[:12])


if __name__ == "__main__":
    main()
