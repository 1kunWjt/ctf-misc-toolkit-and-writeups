# -*- coding: utf-8 -*-
"""
pip 包装器（沙箱环境专用）

问题：本机 Python 3.14 在 Windows 上用 os.mkdir(mode=0o700) 建临时目录时，
会写入一个限制性 DACL；而当前 DSH 沙箱工作区的 ACL 是「低完整性 + 自定义 SID」，
结果这种 0700 目录连自己都写不进去（pip 报 Permission denied，且无法删除）。

方案：把 tempfile.mkdtemp 换成用 os.makedirs(mode=0o777) 的实现（ACL 可继承）。

用法:  python pip_shim.py install --target <dir> <包名> [其余 pip 参数...]
"""
import os
import random
import string
import sys
import tempfile

_ALPHABET = string.ascii_letters + string.digits + "_"


def _mkdtemp(suffix=None, prefix=None, dir=None):
    suffix = suffix or ""
    prefix = prefix or "tmp"
    base = dir or tempfile.gettempdir()
    for _ in range(200):
        name = prefix + "".join(random.choice(_ALPHABET) for _ in range(8)) + suffix
        path = os.path.join(base, name)
        try:
            os.makedirs(path, mode=0o777)      # 关键：可继承 ACL
            return path
        except FileExistsError:
            continue
    raise FileExistsError("无法创建临时目录于 %s" % base)


tempfile.mkdtemp = _mkdtemp
try:
    tempfile.TemporaryDirectory._mkdtemp = staticmethod(_mkdtemp)
except Exception:
    pass


def main():
    from pip._internal.cli.main import main as pip_main
    return pip_main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
