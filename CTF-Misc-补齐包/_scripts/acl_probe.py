# -*- coding: utf-8 -*-
import os
import subprocess
import sys
import tempfile

base = r"D:\XiaoMibook\CTF学习\CTF-Misc-补齐包\.pip-tmp"
os.makedirs(base, exist_ok=True)


def acl(p):
    r = subprocess.run(["icacls", p], capture_output=True)
    return r.stdout.decode("gbk", "replace")


def trywrite(d):
    try:
        with open(os.path.join(d, "t.txt"), "w") as f:
            f.write("x")
        return "OK"
    except Exception as e:
        return "FAIL %s" % type(e).__name__


# 1) 原始 mkdtemp (0700)
d1 = tempfile.mkdtemp(prefix="raw-", dir=base)
print("[1] raw mkdtemp      :", trywrite(d1))
print(acl(d1))
try:
    os.rmdir(d1)
    print("    rmdir: OK")
except Exception as e:
    print("    rmdir FAIL:", type(e).__name__, e)

# 2) rmdir + makedirs(0o777)
d2 = os.path.join(base, "manual-777")
os.makedirs(d2, mode=0o777, exist_ok=True)
print("[2] makedirs 0o777   :", trywrite(d2))

# 3) chmod 后
d3 = tempfile.mkdtemp(prefix="raw2-", dir=base)
try:
    os.chmod(d3, 0o777)
    print("[3] chmod 777 之后   :", trywrite(d3))
except Exception as e:
    print("[3] chmod FAIL", e)

# 4) 用 icacls 显式授权
d4 = tempfile.mkdtemp(prefix="raw3-", dir=base)
u = os.environ.get("USERNAME", "")
r = subprocess.run(["icacls", d4, "/grant", u + ":(OI)(CI)F"], capture_output=True)
print("[4] icacls grant     :", r.returncode, trywrite(d4))

# 5) 父目录 ACL
print("\n父目录 ACL:\n", acl(base))
