# -*- coding: utf-8 -*-
"""
polyroots.py —— 手写「模素数多项式求根」工具（无 sympy，纯标准库）

为什么需要它：
    本题把 RSA 的 p 藏成了一个四次同余方程
        f(x) = x^4 + a*x^2 + b*x - n == 0  (mod P)
    的根。而我们手里只有 + - * // %，没有任何代数库。
    所以这里从零实现：多项式加/乘/除/取模、快速幂、gcd、Cantor-Zassenhaus 分裂。

约定：
    多项式用「低次在前」的 list 表示，系数已经 mod p。
    例如 3 + 2x + x^2  ->  [3, 2, 1]
    所有函数的 modulus 参数 p 必须是素数。
"""

import random


# ----------------------------------------------------------------------------
# 0. 大整数基础件
# ----------------------------------------------------------------------------
def egcd(a, b):
    """扩展欧几里得：返回 (g, x, y) 使 a*x + b*y = g"""
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
    """模逆 a^-1 mod p（p 为素数且 a 不整除 p）"""
    a %= p
    g, x, _ = egcd(a, p)
    if g != 1:
        raise ValueError("no inverse: gcd=%d" % g)
    return x % p


# ----------------------------------------------------------------------------
# 1. 多项式基本运算
# ----------------------------------------------------------------------------
def trim(f):
    """去掉高位 0"""
    while len(f) > 1 and f[-1] == 0:
        f.pop()
    return f


def degree(f):
    f = trim(list(f))
    return 0 if (len(f) == 1 and f[0] == 0) else len(f) - 1


def poly_mod(f, p):
    """所有系数 mod p"""
    return [c % p for c in f]


def poly_add(f, g, p):
    n = max(len(f), len(g))
    out = [0] * n
    for i in range(n):
        out[i] = ((f[i] if i < len(f) else 0) + (g[i] if i < len(g) else 0)) % p
    return trim(out)


def poly_sub(f, g, p):
    n = max(len(f), len(g))
    out = [0] * n
    for i in range(n):
        out[i] = ((f[i] if i < len(f) else 0) - (g[i] if i < len(g) else 0)) % p
    return trim(out)


def poly_mul(f, g, p):
    out = [0] * (len(f) + len(g) - 1)
    for i, c in enumerate(f):
        if c:
            for j, d in enumerate(g):
                if d:
                    out[i + j] = (out[i + j] + c * d) % p
    return trim(out)


def poly_divmod(f, g, p):
    """多项式带余除法 f = q*g + r，返回 (q, r)，系数 mod p"""
    f = trim([c % p for c in f])
    g = trim([c % p for c in g])
    if len(g) == 1 and g[0] == 0:
        raise ZeroDivisionError("divide by zero polynomial")
    inv_lc = inv_mod(g[-1], p)
    q = [0] * max(1, len(f) - len(g) + 1)
    while not (len(f) == 1 and f[0] == 0) and len(f) >= len(g):
        d = len(f) - len(g)
        coef = f[-1] * inv_lc % p
        q[d] = coef
        for i in range(len(g)):
            f[d + i] = (f[d + i] - coef * g[i]) % p
        trim(f)
    return trim(q), trim(f)


def poly_monic(f, p):
    """把 f 化成首一多项式（系数 mod p）"""
    f = trim([c % p for c in f])
    if len(f) == 1 and f[0] == 0:
        return f
    inv = inv_mod(f[-1], p)
    return trim([(c * inv) % p for c in f])


def poly_mod_of(f, m, p):
    """f mod m（多项式取模）"""
    return poly_divmod(f, m, p)[1]


def poly_gcd(f, g, p):
    """多项式 gcd（首一化返回）"""
    f = poly_monic(f, p)
    g = poly_monic(g, p)
    while not (len(g) == 1 and g[0] == 0):
        f, g = g, poly_monic(poly_divmod(f, g, p)[1], p)
    return poly_monic(f, p)


def poly_powmod(base, exp, mod, p):
    """base^exp mod (mod, p)，exp 可以是 512 bit 的大整数"""
    result = [1]
    base = poly_mod_of(base, mod, p)
    while exp > 0:
        if exp & 1:
            result = poly_mul(result, base, p)
            result = poly_mod_of(result, mod, p)
        exp >>= 1
        if exp:
            base = poly_mul(base, base, p)
            base = poly_mod_of(base, mod, p)
    return result


def poly_deriv(f, p):
    """形式导数（求重根判定用）"""
    if len(f) <= 1:
        return [0]
    return trim([(i * f[i]) % p for i in range(1, len(f))])


def poly_squarefree(f, p):
    """squarefree part: f / gcd(f, f')"""
    d = poly_deriv(f, p)
    if len(d) == 1 and d[0] == 0:
        return trim(list(f))
    g = poly_gcd(f, d, p)
    q, _ = poly_divmod(f, g, p)
    return trim(q)


# ----------------------------------------------------------------------------
# 2. 核心：x^p mod f 的 gcd —— 「哪些元素是根」
# ----------------------------------------------------------------------------
def roots_split(f, p):
    """
    第一步：g = gcd(x^p - x, f)
    数学依据：在 GF(p) 上, x^p - x = ∏_{c in GF(p)} (x - c)，
              所以 gcd(x^p - x, f) 恰好是 f 的「所有一次因子的乘积」，
              其次数 = f 在 GF(p) 中互不相同的根的个数。
    返回值：(g, 中间量 dict)
    """
    f = poly_monic(f, p)  # 首一化
    x = [0, 1]
    h = poly_powmod(x, p, f, p)          # h = x^p mod f，次数 < deg f
    h_minus_x = poly_sub(h, x, p)        # x^p - x mod f
    g = poly_gcd(h_minus_x, f, p)
    return g, {"x^p mod f": h, "deg(x^p mod f)": degree(h),
               "deg(g)": degree(g)}


def _equal_degree_split(f, d, p, rng):
    """Cantor-Zassenhaus：把「d 个互不相同的一次因子之积」拆成单个因子"""
    factors = [f]
    out = []
    while factors:
        h = factors.pop()
        dh = degree(h)
        if dh == d:
            out.append(h)
            continue
        while True:
            delta = rng.randrange(1, p)
            # gcd(h, (x+delta)^((p-1)/2) - 1) 会以 ~1/2 概率把 h 劈开
            base = [delta, 1]
            t = poly_powmod(base, (p - 1) // 2, h, p)
            t = poly_sub(t, [1], p)
            g = poly_gcd(t, h, p)
            if 0 < degree(g) < dh:
                factors.append(g)
                factors.append(trim(poly_divmod(h, g, p)[0]))
                break
    return out


def roots_mod_prime(f, p, seed=2024):
    """
    求 f(x) == 0 (mod p) 的全部互异根（p 为素数）。
    返回 (roots, 中间量 dict)
    """
    rng = random.Random(seed)
    f = poly_monic(f, p)                          # 首一化
    f = poly_squarefree(f, p)                     # 去掉重因子
    g, info = roots_split(f, p)
    dg = degree(g)
    info["deg(squarefree f)"] = degree(f)
    if dg == 0:
        return [], info                            # 无根
    if dg == 1:
        gs = [g]
    else:
        gs = _equal_degree_split(g, 1, p, rng)     # 目标：degree 1
    roots = []
    for lin in gs:
        # a*x + b = 0  ->  x = -b / a
        roots.append((-lin[0] * inv_mod(lin[1], p)) % p)
    roots.sort()
    info["num_roots"] = len(roots)
    return roots, info


# ----------------------------------------------------------------------------
# 3. 自测（直接运行本文件时执行）：在已知答案上验证求根器是对的
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    import time
    t0 = time.time()
    P = 1000003
    # (x-1)(x-2)(x-3)(x-4) = x^4 -10x^3 +35x^2 -50x +24
    f = [24, -50, 35, -10, 1]
    roots, info = roots_mod_prime(f, P)
    print("[selftest1] deg(x^p mod f) =", info["deg(x^p mod f)"])
    print("[selftest1] roots =", roots, "expected [1, 2, 3, 4]")
    assert roots == [1, 2, 3, 4]

    # 无根的例子：x^2 + 1 在 mod 3 下无根（3 = 3 mod 4）
    roots2, info2 = roots_mod_prime([1, 0, 1], 3)
    print("[selftest2] roots(x^2+1 mod 3) =", roots2, "expected []")
    assert roots2 == []

    # 只有一个根的例子：x^2 - 4x + 4 = (x-2)^2 -> squarefree 后只剩 2
    roots3, info3 = roots_mod_prime([4, -4, 1], 101)
    print("[selftest3] roots(x^2-4x+4 mod 101) =", roots3, "expected [2]")
    assert roots3 == [2]

    print("[OK] all selftests passed in %.2fs" % (time.time() - t0))
