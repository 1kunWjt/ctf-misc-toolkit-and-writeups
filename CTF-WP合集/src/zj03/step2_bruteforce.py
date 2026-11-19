# -*- coding: utf-8 -*-
"""第03题 第二步：对 38 字符尾巴做系统性解码穷举
思路：先做「字符串层变换」（反转/ROT/栅栏/列换位/大小写/字母表位移），
     再做「编码层解码」（base64 变体 / base62 / base58 / base32 / base85），
     最后用"可打印率 + 是否含花括号/已知前缀"打分。
"""
import base64
import binascii
import codecs
import itertools

S = 'dEFfc1dGq1pxMgMWnihrMx9mewNgdvIWMvctrc'

B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
B62A = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
B62B = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
B58BTC = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58FLK = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
B58RIP = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'


def score(b):
    """给解码结果打分：可打印率越高越好；命中 flag 特征额外加分"""
    if not b:
        return -1, ''
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    r = printable / len(b)
    bonus = 0
    if b'{' in b and b'}' in b:
        bonus += 30
    if b'DASCTF' in b or b'flag' in b or b'ctf' in b.lower():
        bonus += 20
    if b.startswith((b'PK', b'\x89PNG', b'\x1f\x8b', b'\x78\x9c')):
        bonus += 15
    return r * 100 + bonus, r


def try_decoders(name, s, out):
    """对字符串 s 尝试各种解码，把像样的结果塞进 out"""
    variants = []

    def add(tag, fn):
        try:
            r = fn()
            if isinstance(r, str):
                r = r.encode('latin-1')
            if r:
                variants.append((tag, r))
        except Exception:
            pass

    # --- base64 家族（含补 '=' 的各种情况）---
    def b64(s, alt=B64):
        t = s
        if len(t) % 4:
            t += '=' * (4 - len(t) % 4)
        std = B64
        if alt != std:
            t = t.translate(str.maketrans(alt, std))
        return base64.b64decode(t, validate=False)

    add('b64', lambda: b64(s))
    add('b64url', lambda: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)))
    # 自定义字母表：标准表整体旋转 k 位
    for k in range(1, 64):
        alt = B64[k:] + B64[:k]
        add('b64rot%d' % k, lambda alt=alt: b64(s, alt))
    # 标准表反转
    add('b64rev-alpha', lambda: b64(s, B64[::-1]))
    # 大小写互换后再解
    add('b64-sswap', lambda: b64(s.swapcase()))

    # --- base62（大整数）---
    def base62(s, alpha=B62A):
        n = 0
        for ch in s:
            n = n * 62 + alpha.index(ch)
        ln = (n.bit_length() + 7) // 8
        return n.to_bytes(ln, 'big')

    add('b62num', lambda: base62(s))
    add('b62num-B', lambda: base62(s, B62B))
    # base62 直接 6bit 位流
    def base62bits(s, alpha=B62A):
        bits = ''.join(format(alpha.index(ch), '06b') for ch in s)
        bits = bits[:len(bits) // 8 * 8]
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

    add('b62bits', lambda: base62bits(s))
    add('b62bits-B', lambda: base62bits(s, B62B))

    # --- base58 ---
    def base58(s, alpha):
        n = 0
        for ch in s:
            n = n * 58 + alpha.index(ch)
        ln = (n.bit_length() + 7) // 8
        pad = len(s) - len(s.lstrip(alpha[0]))
        return b'\x00' * pad + n.to_bytes(ln, 'big')

    for nm, al in (('b58btc', B58BTC), ('b58flickr', B58FLK), ('b58ripple', B58RIP)):
        if all(c in al for c in s):
            add(nm, lambda al=al: base58(s, al))

    # --- base32 / base85 ---
    add('b32', lambda: base64.b32decode(s.upper() + '=' * (-len(s) % 8)))
    add('b85', lambda: base64.b85decode(s))
    add('a85', lambda: base64.a85decode(s))

    # --- 十六进制（若全是 hex 字符）---
    if all(c in '0123456789abcdefABCDEF' for c in s) and len(s) % 2 == 0:
        add('hex', lambda: bytes.fromhex(s))

    for tag, r in variants:
        sc, pr = score(r)
        out.append((sc, '%s|%s' % (name, tag), r))


# ---------------- 字符串层变换 ----------------
def rev(s):
    return s[::-1]


def rot13(s):
    return codecs.encode(s, 'rot13')


def atbash(s):
    tbl = {}
    for i in range(26):
        tbl[ord('a') + i] = ord('z') - i
        tbl[ord('A') + i] = ord('Z') - i
    return s.translate(tbl)


def caesar(s, k):
    o = []
    for ch in s:
        if 'a' <= ch <= 'z':
            o.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif 'A' <= ch <= 'Z':
            o.append(chr((ord(ch) - 65 + k) % 26 + 65))
        else:
            o.append(ch)
    return ''.join(o)


def rot47(s):
    return ''.join(chr((ord(c) - 33 + 47) % 94 + 33) if 33 <= ord(c) <= 126 else c for c in s)


def rail_fence_dec(s, n):
    """栅栏密码解密（按 zigzag 填回轨道再顺序读）"""
    L = len(s)
    pat = []
    r = 0
    step = 1
    for _ in range(L):
        pat.append(r)
        if r == 0:
            step = 1
        elif r == n - 1:
            step = -1
        r += step
    order = sorted(range(L), key=lambda i: (pat[i], i))
    out = [''] * L
    for ch, idx in zip(s, order):
        out[idx] = ch
    return ''.join(out)


def rail_fence_enc(s, n):
    """栅栏加密（按 zigzag 读）"""
    L = len(s)
    pat = []
    r = 0
    step = 1
    for _ in range(L):
        pat.append(r)
        if r == 0:
            step = 1
        elif r == n - 1:
            step = -1
        r += step
    return ''.join(s[i] for i in range(L) if pat[i] == rr for rr in [])


def rail_enc(s, n):
    L = len(s)
    pat = []
    r = 0
    step = 1
    for _ in range(L):
        pat.append(r)
        if r == 0:
            step = 1
        elif r == n - 1:
            step = -1
        r += step
    res = []
    for rr in range(n):
        res.extend(s[i] for i in range(L) if pat[i] == rr)
    return ''.join(res)


def coldec(s, c):
    """列换位解密：按 c 列写入、按行读出 -> 逆过程"""
    L = len(s)
    rows = (L + c - 1) // c
    pad = rows * c - L
    # 加密：明文按行填满 rows*c，然后按列读出（最后一列可能不满）
    cols = []
    i = 0
    for cc in range(c):
        n = rows if cc < c - pad else rows - 1
        cols.append(s[i:i + n])
        i += n
    out = []
    for r in range(rows):
        for cc in range(c):
            if r < len(cols[cc]):
                out.append(cols[cc][r])
    return ''.join(out)


def colenc(s, c):
    L = len(s)
    rows = (L + c - 1) // c
    grid = [s[i * c:(i + 1) * c] for i in range(rows)]
    out = []
    for cc in range(c):
        for r in range(rows):
            if cc < len(grid[r]):
                out.append(grid[r][cc])
    return ''.join(out)


def main():
    s = S
    names = {}
    variants = []

    def add(tag, v):
        if v not in names:
            names[v] = tag
            variants.append(v)

    add('id', s)
    add('rev', rev(s))
    add('rot13', rot13(s))
    add('rot13+rev', rot13(rev(s)))
    add('rev+rot13', rev(rot13(s)))
    add('atbash', atbash(s))
    add('atbash+rev', atbash(rev(s)))
    add('swapcase', s.swapcase())
    add('swapcase+rev', rev(s.swapcase()))
    add('rot47', rot47(s))
    add('rot47+rev', rot47(rev(s)))
    for k in range(1, 26):
        add('caesar%d' % k, caesar(s, k))
        add('caesar%d+rev' % k, rev(caesar(s, k)))
    for n in range(2, 11):
        add('rail.DEC%d' % n, rail_fence_dec(s, n))
        add('rail.ENC%d' % n, rail_enc(s, n))
    for c in range(2, 13):
        add('coldec%d' % c, coldec(s, c))
        add('colenc%d' % c, colenc(s, c))
    add('upper', s.upper())
    add('lower', s.lower())

    out = []
    for v in variants:
        try_decoders(names[v], v, out)

    out.sort(key=lambda x: -x[0])
    print('[INFO] string variants tried = %d, decode results = %d' % (len(variants), len(out)))
    print('=' * 78)
    seen = set()
    shown = 0
    for sc, tag, r in out:
        if r in seen:
            continue
        seen.add(r)
        pr = sum(1 for x in r if 32 <= x < 127) / len(r)
        if pr < 0.85:
            continue
        shown += 1
        print('[HIT] score=%.1f  %-28s  len=%d' % (sc, tag, len(r)))
        print('      %r' % r[:120])
        if shown >= 40:
            break
    print('=' * 78)
    print('[INFO] printable-ish results = %d' % shown)


if __name__ == '__main__':
    main()
