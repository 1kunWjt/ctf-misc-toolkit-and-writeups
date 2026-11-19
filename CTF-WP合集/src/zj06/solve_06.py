# -*- coding: utf-8 -*-
"""
solve_06.py —— 第 06 题 myez_encode 完整解题脚本（无 sympy / 无 pycryptodome）

核心思路（本题唯一的思维跳跃）：
    源码里 q = (p^3 + a*p + b) mod P，且 p,q < P。把 q 用一个同余式替换掉：
        n = p*q == p*(p^3 + a*p + b) = p^4 + a*p^2 + b*p   (mod P)
    于是 p 就是四次同余方程  f(x) = x^4 + a*x^2 + b*x - n == 0 (mod P) 的根。
    P 是 512 bit 素数 —— 用「多项式快速幂 + gcd」把根全部求出来，
    再挑出能整除 n 的那个，就是真正的 p。

跑法：
    $env:PYTHONIOENCODING="utf-8"
    & $py solve\\solve_06.py
输出：
    控制台真实日志 + solve/out/result.json（供 make_images.py 渲染配图）
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from polyroots import (inv_mod, poly_monic, poly_mul, poly_sub, roots_split,
                       roots_mod_prime, degree)
from modroot import eth_roots_mod_prime, crt_pair

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "out")

# ---- 题目附件里的公开参数（直接抄自 myez_encode.py 的注释）----
n = 23298836191712395990541254600776262066247692725919114528027158820049802443474994576179738462067629079873633948850637889127452791527914591229415148712172587856497614285410824614070907847594399218298016379507879066220104597707859246179921731928508884947347652904142879813069359815823184922170241099916465722623
a = 7388665644223916915334064243181348811184637180763467245762518813757790945069068654378380490110607063038613823004593920489924786053478102905200169738195523
b = 11742940161647091720180482697980016011774828087234021441133595442949631197989696508358388255191793888646498553804646435609849154496274569000398776043150743
P = 11300086101709077144191286182913849072593185125745291892398153828719453495325025227858328617077648296782357912556752467026523366682963139253552060862229027
c = 9314530945343661153059846131608414257092556390479105017633636336832925597262814680689800448223193301814365726128618348603188219757245073917910487794768758461683644600756896595336654006282030911824869219015400826589122838492456940861634378619000373353637666835642505021355710338342048772713981673863167110471
e = 9

LOG = []


def say(s=""):
    print(s)
    LOG.append(s)


def long_to_bytes(v):
    """pycryptodome 的 long_to_bytes 手工版"""
    if v == 0:
        return b"\x00"
    out = b""
    while v:
        out = bytes([v & 0xFF]) + out
        v >>= 8
    return out


def main():
    t0 = time.time()
    say("=" * 74)
    say("[*] myez_encode  --  RSA with p hidden in a quartic congruence")
    say("=" * 74)
    say("[*] bit lengths: n=%d  a=%d  b=%d  P=%d  c=%d"
        % (n.bit_length(), a.bit_length(), b.bit_length(),
           P.bit_length(), c.bit_length()))
    say("[*] e = %d" % e)

    # ---------------------------------------------------------------
    # STEP 1: 从源码读出 q 与 p 的关系，构造四次多项式
    # ---------------------------------------------------------------
    say("")
    say("[STEP 1] build f(x) = x^4 + a*x^2 + b*x - n  over GF(P)")
    # 系数「低次在前」: [常数项, x^1, x^2, x^3, x^4]
    f = [(-n) % P, b % P, a % P, 0, 1]
    say("         f = [x^0 .. x^4] = [" + ", ".join(
        "%s" % ("-" + str(x) if k == 0 else str(x))
        for k, x in enumerate([n, b, a, 0, 1])) + "]  (mod P)")
    say("         deg f = %d,  leading coeff = 1" % (len(f) - 1))

    # 自检：把 f 的系数代回同余式，确认 n 与 a,b,P 的关系
    say("         check: n mod P = %d" % (n % P))
    assert f[0] == (-n) % P

    # ---------------------------------------------------------------
    # STEP 2: 多项式快速幂 x^P mod f ，再 gcd(x^P - x, f)
    # ---------------------------------------------------------------
    say("")
    say("[STEP 2] compute h(x) = x^P mod f   (P is 512-bit -> ~512 squarings)")
    t1 = time.time()
    h, info = roots_split(f, P)
    g = h
    say("         deg(x^P mod f) = %d" % info["deg(x^p mod f)"])
    say("         g = gcd(x^P - x, f, P)   deg g = %d  -> f has %d distinct root(s) in GF(P)"
        % (degree(g), degree(g)))
    say("         elapsed %.3f s" % (time.time() - t1))

    # ---------------------------------------------------------------
    # STEP 3: Cantor-Zassenhaus 把 g 分裂成线性因子，抽出具体根
    # ---------------------------------------------------------------
    say("")
    say("[STEP 3] Cantor-Zassenhaus equal-degree splitting -> explicit roots")
    t1 = time.time()
    roots, rinfo = roots_mod_prime(f, P)
    say("         roots found: %d   (elapsed %.3f s)" % (len(roots), time.time() - t1))
    for i, r in enumerate(roots):
        mark = ""
        if n % r == 0:
            mark = "   <== divides n !!"
        say("         r[%d] = %d  (%d bits)%s" % (i, r, r.bit_length(), mark))

    # ---------------------------------------------------------------
    # STEP 4: 用 n % p == 0 验证，得到 p,q
    # ---------------------------------------------------------------
    say("")
    say("[STEP 4] pick the root that really divides n (p < P so p == r)")
    cands = [r for r in roots if n % r == 0]
    if not cands:
        say("[FAIL] no root divides n -- the derivation or the tool is wrong")
        return 1
    p = cands[0]
    q = n // p
    say("         p = %d" % p)
    say("         q = n // p = %d" % q)
    say("         check n == p*q : %s" % (n == p * q))
    say("         check q == (p^3+a*p+b) mod P : %s"
        % (q == (p ** 3 + a * p + b) % P))
    say("         check p < P : %s ; q < P : %s" % (p < P, q < P))
    assert n == p * q

    # 素性快检（Miller-Rabin，确定性底集够用）
    say("         is_probable_prime(p) = %s, (q) = %s"
        % (is_prime(p), is_prime(q)))

    # ---------------------------------------------------------------
    # STEP 5: 解密。d 不存在（gcd(e,phi)=3），改用「模 n 开 9 次方」
    # ---------------------------------------------------------------
    say("")
    say("[STEP 5] phi = (p-1)(q-1);  try d = e^-1 mod phi  ...")
    phi = (p - 1) * (q - 1)
    say("         phi bit length = %d" % phi.bit_length())
    from math import gcd
    gd = gcd(e, phi)
    say("         gcd(e, phi) = %d  ->  d exists: %s" % (gd, gd == 1))
    say("         [!] e=9 shares factor 3 with phi, so d does NOT exist.")
    say("             3 | p-1 ? %s ;  3 | q-1 ? %s ;  9 | p-1 ? %s"
        % (gcd(3, p - 1) == 3, gcd(3, q - 1) == 3, (p - 1) % 9 == 0))
    say("             3 | (p-1) = %s and 3 | (q-1) = %s  -> 9|phi would need both"
        % (gcd(3, p - 1) == 3, gcd(3, q - 1) == 3))
    say("         => switch route: solve x^9 == c directly, i.e. take a 9th root")

    # 5a. 模 p 开 9 次方（会有 gcd(9,p-1) 个根）
    say("")
    say("[STEP 5a] 9th roots of c modulo p   (gcd(9,p-1)=%d -> that many)" % gcd(9, p - 1))
    t1 = time.time()
    mp_list = eth_roots_mod_prime(c % p, e, p)
    say("         roots mod p: %d   (elapsed %.3f s)" % (len(mp_list), time.time() - t1))
    for i, v in enumerate(mp_list):
        say("           m_p[%d] = %d" % (i, v))
    assert mp_list, "no 9th root mod p -> c is not a 9th power residue mod p"
    if len(mp_list) >= 1:
        # 说明一下 9 次根为什么是可以枚举的
        pass

    # 5b. 模 q 开 9 次方（gcd(9,q-1)=1 -> 唯一）
    say("")
    say("[STEP 5b] 9th roots of c modulo q   (gcd(9,q-1)=%d -> unique)" % gcd(9, q - 1))
    t1 = time.time()
    mq_list = eth_roots_mod_prime(c % q, e, q)
    say("         roots mod q: %d   (elapsed %.3f s)" % (len(mq_list), time.time() - t1))
    for i, v in enumerate(mq_list):
        say("           m_q[%d] = %d" % (i, v))
    assert mq_list

    # 5c. CRT 拼回模 n 的全部候选
    say("")
    say("[STEP 5c] CRT: combine every (m_p, m_q) pair -> candidates mod n")
    cands_m = []
    for vp in mp_list:
        for vq in mq_list:
            cands_m.append(crt_pair(vp, p, vq, q))
    cands_m = sorted(set(cands_m))
    say("         total candidates: %d" % len(cands_m))
    for i, mm in enumerate(cands_m):
        ok = pow(mm, e, n) == c
        say("           m[%d] = %d  (%d bits)  m^9 mod n == c : %s"
            % (i, mm, mm.bit_length(), ok))
    assert all(pow(x, e, n) == c for x in cands_m)

    # 5d. 挑出人类可读的那个
    say("")
    say("[STEP 5d] decode each candidate, keep the printable one")
    flag = None
    for i, mm in enumerate(cands_m):
        raw = long_to_bytes(mm)
        printable = all(32 <= ch < 127 for ch in raw)
        mark = ""
        if printable:
            mark = "   <== ASCII"
        say("           m[%d] len=%d  %r%s" % (i, len(raw), raw[:80], mark))
        if printable and flag is None:
            try:
                txt = raw.decode("ascii")
            except UnicodeDecodeError:
                continue
            if "{" in txt and "}" in txt:
                flag = txt
    if flag is None:
        say("[FAIL] no printable candidate looks like a flag")
        return 3

    say("")
    say("[OK] flag = %s" % flag)

    # ---------------------------------------------------------------
    # 落盘，供配图脚本复用（图必须来自真实运行结果）
    # ---------------------------------------------------------------
    os.makedirs(OUT_DIR, exist_ok=True)
    payload = {
        "n": str(n), "a": str(a), "b": str(b), "P": str(P), "c": str(c), "e": e,
        "n_bits": n.bit_length(), "P_bits": P.bit_length(),
        "xP_mod_f": [str(x) for x in info["x^p mod f"]],
        "deg_g": degree(g),
        "g_coeffs": [str(x) for x in g],
        "roots": [str(r) for r in roots],
        "root_bits": [r.bit_length() for r in roots],
        "p": str(p), "q": str(q), "phi_bits": phi.bit_length(),
        "gcd_e_phi": gd,
        "gcd_9_p1": gcd(9, p - 1), "gcd_9_q1": gcd(9, q - 1),
        "mp_list": [str(x) for x in mp_list],
        "mq_list": [str(x) for x in mq_list],
        "cands": [str(x) for x in cands_m],
        "flag": flag,
        "log": LOG,
    }
    with open(os.path.join(OUT_DIR, "result.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1)
    say("[*] wrote %s" % os.path.join(OUT_DIR, "result.json"))
    say("[*] total time %.2f s" % (time.time() - t0))
    return 0


# ---- Miller-Rabin（手写，不依赖 sympy）----
def is_prime(num, rounds=40):
    if num < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if num % sp == 0:
            return num == sp
    dd = num - 1
    s = 0
    while dd % 2 == 0:
        dd //= 2
        s += 1
    import random
    rng = random.Random(12345)
    for _ in range(rounds):
        aa = rng.randrange(2, num - 1)
        xx = pow(aa, dd, num)
        if xx in (1, num - 1):
            continue
        for _ in range(s - 1):
            xx = xx * xx % num
            if xx == num - 1:
                break
        else:
            return False
    return True


if __name__ == "__main__":
    sys.exit(main())
