# -*- coding: utf-8 -*-
"""
modroot.py —— 模素数开 e 次根（手写 AMM / Adleman-Manders-Miller）

为什么需要它：
    RSA 解密的标准做法是 d = e^{-1} mod phi。但本题 gcd(e=9, phi) = 3，
    d 根本不存在 —— 这时候不能套公式，得回到「解方程」的本意：
        x^9 == c (mod n)
    开 9 次方（不是求逆），分别对 p、q 开方后用 CRT 拼回来；
    因为 3 | p-1，所以模 p 那一侧会有 3 个根，最终共有 3 个候选 m。

前置数学（x^r = a mod p, r 为素数）：
    (1) 判定 a 是不是 r 次剩余：a^((p-1)/r) == 1。
    (2) 把 p-1 写成 r^s * t（gcd(r,t)=1）。写 r*f = 1 + k*t，
        则 x0 = a^f 满足 x0 = x * w^j，其中 w = rho^t 是 r^s 次单位根
        （rho 取任意非 r 次剩余），j 是唯一待定的小指数。
    (3) 由 c = x0^r / a = w^(j*r) 在 <w^r>（阶 r^(s-1)）中暴力定出 j 即可。
        暴力范围只有 r^(s-1)，r=3、s=1 时就是 1 个值 —— 几乎零成本。
    (4) 所有根 = x * ζ^i，ζ = w^(r^(s-1)) 是 r 次本原单位根。
"""

import random


def egcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def inv_mod(a, p):
    a %= p
    g, x, _ = egcd(a, p)
    if g != 1:
        raise ValueError("no inverse: gcd=%d" % g)
    return x % p


def rth_roots_mod_prime(a, r, p, seed=7):
    """
    返回 x^r == a (mod p) 的全部解（r 是素数，p 是素数）。
    a 不是 r 次剩余时返回 []。
    """
    a %= p
    if a == 0:
        return [0]
    # ---- p-1 = r^s * t ----
    s, t = 0, p - 1
    while t % r == 0:
        t //= r
        s += 1
    if s == 0:
        # gcd(r, p-1) = 1：开方就是求逆，唯一解，无需 AMM
        return [pow(a, inv_mod(r, p - 1), p)]
    if pow(a, (p - 1) // r, p) != 1:
        return []                      # 非 r 次剩余，无解
    if t == 1:
        # 极端情形 p-1 是 r 的纯幂，此时 a^f 那套退化；
        # 本题不会走到（t 都是几百 bit 的大数）
        raise ValueError("degenerate: p-1 is a pure power of r")

    # ---- 找一个非 r 次剩余 rho，构造 r^s 次单位根 w ----
    rng = random.Random(seed)
    while True:
        rho = rng.randrange(2, p - 1)
        if pow(rho, (p - 1) // r, p) != 1:
            break
    w = pow(rho, t, p)                 # w 的阶 = r^s
    w_inv = inv_mod(w, p)

    # ---- x0 = a^f,  r*f = 1 + k*t ----
    f = inv_mod(r % t, t)
    x0 = pow(a, f, p)
    c = pow(x0, r, p) * inv_mod(a, p) % p      # c = w^(j*r)
    j = None
    for jj in range(r ** (s - 1)):
        if pow(w, jj * r, p) == c:
            j = jj
            break
    if j is None:
        raise RuntimeError("AMM failed to determine j")
    x = x0 * pow(w_inv, j, p) % p

    # ---- 乘上 r 次单位根，拿到全部 r 个解 ----
    zeta = pow(w, r ** (s - 1), p)     # r 次本原单位根
    out = []
    cur = x
    for _ in range(r):
        out.append(cur)
        cur = cur * zeta % p
    out = sorted(set(out))
    for v in out:                      # 自检
        assert pow(v, r, p) == a, "AMM produced a non-root"
    return out


def eth_roots_mod_prime(a, e, p, seed=7):
    """
    x^e == a (mod p) 的全部解。e 只做小素数分解（本题 e=9=3*3）。
    做法：逐层开素数方，每层收集所有分支，最后验算去重。
    """
    a %= p
    # 小整数分解 e
    fac, m, d = [], e, 2
    while d * d <= m:
        while m % d == 0:
            fac.append(d)
            m //= d
        d += 1
    if m > 1:
        fac.append(m)

    layer = [a]
    for prime in fac:
        nxt = []
        for v in layer:
            nxt.extend(rth_roots_mod_prime(v, prime, p, seed))
        layer = sorted(set(nxt))
        if not layer:
            return []
    return [v for v in layer if pow(v, e, p) == a % p]


def crt_pair(a1, m1, a2, m2):
    """中国剩余定理：返回唯一的 x mod m1*m2（要求 gcd(m1,m2)=1）"""
    g, s, _ = egcd(m1, m2)
    if g != 1:
        raise ValueError("CRT needs coprime moduli")
    x = (a1 + (a2 - a1) * s % m2 * m1) % (m1 * m2)
    return x


def long_to_bytes(v):
    if v == 0:
        return b"\x00"
    out = b""
    while v:
        out = bytes([v & 0xFF]) + out
        v >>= 8
    return out


if __name__ == "__main__":
    # 自测：小素数上暴力对照
    import itertools
    for p, e in ((101, 3), (103, 3), (19, 9), (37, 9), (97, 9)):
        for a in range(1, p):
            brute = sorted(x for x in range(p) if pow(x, e, p) == a)
            got = sorted(eth_roots_mod_prime(a, e, p))
            if brute != got:
                print("[FAIL] p=%d e=%d a=%d  brute=%s got=%s"
                      % (p, e, a, brute, got))
                raise SystemExit(1)
        print("[OK] p=%-4d e=%d  all %d residues agree with brute force"
              % (p, e, p - 1))
    print("[OK] modroot selftest passed")
