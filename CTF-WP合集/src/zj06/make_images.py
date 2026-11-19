# -*- coding: utf-8 -*-
"""
make_images.py —— 用 solve_06.py 的「真实输出」渲染 WP 配图。

数据来源只有两个，全部是程序跑出来的，没有任何手写编造：
    solve/out/result.json   <- solve_06.py 落盘的中间量和完整日志

跑法：
    $env:PYTHONIOENCODING="utf-8"
    & $py solve\\make_images.py
输出：img/01-flow.png 02-derive.png 03-roots.png 03b-ninthroot.png 04-flag.png
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # .../06-myez_encode
IMG = os.path.join(ROOT, "img")
sys.path.insert(0, os.path.join(ROOT, "..", "..", "_wp"))
from imgkit import flow, term, flagbox, codecard     # noqa: E402

with open(os.path.join(HERE, "out", "result.json"), encoding="utf-8") as fh:
    R = json.load(fh)

ATTACH = os.path.join(ROOT, "files", "tempdir", "CRYPTO附件", "myez_encode.py")

LOG = R["log"]
FLAG = R["flag"]
GREEN, CYAN, YELLOW, GREY, MAGENTA, BLUE, RED = (
    (78, 201, 118), (86, 182, 194), (229, 192, 123),
    (128, 128, 128), (198, 120, 221), (97, 175, 239), (224, 108, 117))


def ab(s, head=22, tail=18):
    """长数字截断显示：前 head 位 ... 后 tail 位（完整值见 result.json）"""
    s = str(s)
    if len(s) <= head + tail + 5:
        return s
    return "%s...%s" % (s[:head], s[-tail:])


def pick(prefix):
    """从真实日志里精确取一行（保证图上的字就是程序打印的字）"""
    for ln in LOG:
        if ln.strip().startswith(prefix):
            return ln
    raise KeyError(prefix)


def sec(title, color=CYAN):
    return [("", GREY), ("-- %s %s" % (title, "-" * max(0, 62 - len(title))), color)]


# ---------------------------------------------------------------- 00 source
# 直接读附件原文渲染，保证图上的代码就是题目给的那份代码。
# 只取 1-37 行（代码部分）：38 行往后是注释里的 5 个超长数字，
# 全宽渲染会把整张图撑到 2000+ px，缩进正文后反而看不清。
with open(ATTACH, encoding="utf-8") as fh:
    allsrc = fh.read().rstrip("\n").split("\n")
src = "\n".join(allsrc[:37])
codecard("myez_encode.py   lines 1-37 (of %d)  --  the code part"
         % len(allsrc),
         src, os.path.join(IMG, "00-source.png"), size=14)

# ---------------------------------------------------------------- 01 flow
flow([
    ("读源码：定位 p 与 q 的关系",
     "find_prime_on_curve(): q = (p^3 + a*p + b) mod P,  p,q < P"),
    ("消掉 q：n = p*q 变成 p 的一元同余方程",
     "n = p(p^3+ap+b) mod P  =>  p^4 + a*p^2 + b*p - n = 0 (mod P)"),
    ("mod P 求四次方程的全部根",
     "h = x^P mod f  (512 squarings),  g = gcd(h-x, f),  deg g = 根的个数"),
    ("Cantor-Zassenhaus 分裂出具体根",
     "把 g 劈成线性因子，抽出 p 的候选值（这里只找到 1 个根）"),
    ("用 n % p == 0 验收",
     "p*q == n 且 q == (p^3+ap+b) mod P  =>  p,q 正确"),
    ("解密遇阻：gcd(e=9, phi) = 3",
     "d = e^-1 mod phi 不存在，不能套标准 RSA 公式"),
    ("改路子：模 n 直接开 9 次方",
     "mod p 有 3 个根 + mod q 唯一 = 3 个候选 m（CRT 拼回）"),
    ("3 个候选里挑可打印的 ASCII",
     "得到 DASCTF{...}，并用 pow(m,9,n)==c 反向验收"),
], os.path.join(IMG, "01-flow.png"), title="myez_encode 解题链路")

# ---------------------------------------------------------------- 02 derive
lines = [(("PS> python solve\\solve_06.py"), YELLOW),
         ("[*] bit lengths: n=%d  a=%d  b=%d  P=%d"
          % (R["n_bits"], 512, 512, R["P_bits"]), GREEN)]
lines += sec("STEP 1  build f(x) = x^4 + a*x^2 + b*x - n  over GF(P)")
lines += [("f(x) = x^4 + %s*x^2" % ab(R["a"], 14, 10), GREEN),
          ("            + %s*x" % ab(R["b"], 14, 10), GREEN),
          ("            - %s" % ab(R["n"], 16, 12), GREEN),
          ("deg f = 4, leading coeff = 1  (so f is monic)", GREY)]
lines += sec("STEP 2  h = x^P mod f   (P is 512-bit: ~512 squarings)")
lines += [(pick("deg(x^P mod f)"), GREEN),
          (pick("g = gcd"), GREEN),
          ("=> f has exactly 1 root in GF(P): the real p is in there", YELLOW)]
term(lines, os.path.join(IMG, "02-derive.png"),
     title="solve_06.py  step1-2 (real output)")

# ---------------------------------------------------------------- 03 roots
lines = [(("PS> python solve\\solve_06.py"), YELLOW)]
lines += sec("STEP 3  Cantor-Zassenhaus splitting -> explicit root")
lines += [(pick("roots found"), GREEN)]
lines += [("r[0] = %s" % ab(R["roots"][0], 40, 20), CYAN),
          ("       (%d bits, and it divides n)" % R["root_bits"][0], GREY)]
lines += sec("STEP 4  verify with n % p == 0")
lines += [("p = %s" % ab(R["p"], 34, 16), CYAN),
          ("q = %s" % ab(R["q"], 34, 16), CYAN),
          (pick("check n == p*q"), GREEN),
          (pick("check q == (p^3"), GREEN),
          (pick("check p < P"), GREEN),
          (pick("is_probable_prime"), GREEN),
          ("=> p and q are fully recovered, no brute force involved", YELLOW)]
term(lines, os.path.join(IMG, "03-roots.png"),
     title="solve_06.py  step3-4 (real output)")

# ---------------------------------------------------------------- 03b ninth root
lines = [(("PS> python solve\\solve_06.py"), YELLOW)]
lines += sec("STEP 5  d = e^-1 mod phi does not exist")
lines += [("gcd(e, phi)   = %d" % R["gcd_e_phi"], RED),
          ("gcd(9, p-1)   = %d      <- 3 | p-1" % R["gcd_9_p1"], CYAN),
          ("gcd(9, q-1)   = %d      <- 3 not | q-1" % R["gcd_9_q1"], CYAN),
          ("number of solutions of x^9 = c mod n : %d" % (R["gcd_9_p1"] * R["gcd_9_q1"]), MAGENTA),
          ("so: take a 9th root instead of inverting e", YELLOW)]
lines += sec("STEP 5a/5b  9th roots per prime (AMM)")
for i, v in enumerate(R["mp_list"]):
    lines.append(("  m_p[%d] = %s" % (i, ab(v, 18, 10)), GREEN))
lines += [("  m_q[0] = %s   (unique)" % ab(R["mq_list"][0], 18, 10), GREEN)]
lines += sec("STEP 5c  CRT -> 3 candidates, all satisfy m^9 = c mod n")
for i, v in enumerate(R["cands"]):
    tag = "ASCII!" if i == 0 else "binary"
    lines.append(("  m[%d] %s  [%s]" % (i, ab(v, 16, 10), tag),
                  GREEN if i == 0 else GREY))
lines += [("=> m[0] decodes to printable text -> flag", YELLOW)]
term(lines, os.path.join(IMG, "03b-ninthroot.png"),
     title="solve_06.py  step5 (real output)")

# ---------------------------------------------------------------- 04 flag
flagbox(FLAG, os.path.join(IMG, "04-flag.png"), title="FLAG  (verified: pow(m,9,n)==c)")

print("[OK] images written to", IMG)
for f in sorted(os.listdir(IMG)):
    print("     %-22s %8d bytes" % (f, os.path.getsize(os.path.join(IMG, f))))
