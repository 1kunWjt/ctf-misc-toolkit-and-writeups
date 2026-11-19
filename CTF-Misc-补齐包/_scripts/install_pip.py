# -*- coding: utf-8 -*-
"""为各工具建立独立的 python 库目录（pip --target），互不污染系统环境。"""
import os
import subprocess
import sys

ROOT = r"D:\XiaoMibook\CTF学习\CTF-Misc-补齐包"
PY = sys.executable

# (工具名, 相对目录, pip 参数列表)
JOBS = [
    ("pycryptodome", r"05-密码学\pycryptodome\lib", ["pycryptodome"]),
    ("gmpy2", r"05-密码学\gmpy2\lib", ["gmpy2"]),
    ("z3-solver", r"05-密码学\z3\lib", ["z3-solver"]),
    ("volatility3", r"02-取证工具\Volatility3\lib", ["volatility3"]),
    ("stegoveritas", r"01-隐写工具\StegoVeritas\lib", ["stegoveritas"]),
    ("binwalk", r"04-文件与十六进制\binwalk\lib", ["binwalk"]),
]


def run(args, cwd=None):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    os.makedirs(ROOT, exist_ok=True)
    shim = os.path.join(ROOT, "_scripts", "pip_shim.py")
    # 沙箱内 pip 的临时目录必须放在工作区，且用 pip_shim 绕开 0700 ACL 问题
    tmp = os.path.join(ROOT, ".pip-tmp")
    os.makedirs(tmp, exist_ok=True)
    os.environ["TMP"] = os.environ["TEMP"] = os.environ["TMPDIR"] = tmp
    report = []
    # Typhon 用本地 whl 装
    whl_dir = os.path.join(ROOT, r"03-MISC解题\Typhon")
    if os.path.isdir(whl_dir):
        whls = [f for f in os.listdir(whl_dir) if f.endswith(".whl")]
        if whls:
            JOBS.append(("Typhon", r"03-MISC解题\Typhon\lib",
                         [os.path.join(whl_dir, whls[0])]))

    for name, rel, pkgs in JOBS:
        target = os.path.join(ROOT, rel)
        os.makedirs(target, exist_ok=True)
        if os.listdir(target):
            print("[SKIP] %-16s 已装好" % name, flush=True)
            report.append((name, "已存在"))
            continue
        cmd = [PY, shim, "install", "--no-cache-dir", "--disable-pip-version-check",
               "--no-warn-script-location", "--target", target] + pkgs
        rc, out = run(cmd)
        tail = "\n".join([l for l in out.strip().splitlines() if l.strip()][-3:])
        if rc == 0:
            print("[OK]   %-16s -> %s" % (name, rel), flush=True)
            report.append((name, "OK"))
        else:
            print("[FAIL] %-16s rc=%s | %s" % (name, rc, tail[-200:]), flush=True)
            report.append((name, "FAIL: " + tail[-160:]))

    print("\n== pip 汇总 ==")
    for n, s in report:
        print("%-16s %s" % (n, s))


if __name__ == "__main__":
    main()
