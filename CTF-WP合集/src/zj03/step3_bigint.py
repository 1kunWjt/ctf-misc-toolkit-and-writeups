# -*- coding: utf-8 -*-
"""第03题 第三步：换一种思路 —— 假设密文是「大整数进制编码」，逐个字母表试
重点：base62/base36/base58 的字母表顺序有 6 种常见写法，顺序错了就全是乱码。
另外也试 base64 的「6bit 位流」与「仿射/XOR 换表」。
"""
import base64
import itertools

S = 'dEFfc1dGq1pxMgMWnihrMx9mewNgdvIWMvctrc'

ALPHAS = {
    '09AZaz': '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'AZaz09': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    'azAZ09': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    '09azAZ': '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'AZ09az': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz',
    'az09AZ': 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
}


def bigdecode(s, alpha):
    base = len(alpha)
    n = 0
    for ch in s:
        n = n * base + alpha.index(ch)
    ln = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(ln, 'big')


def show(tag, b):
    pr = sum(1 for x in b if 32 <= x < 127) / max(1, len(b))
    flag = ' <== PRINTABLE' if pr > 0.9 else ''
    print('  %-24s len=%-3d pr=%.2f  %s%s' % (tag, len(b), pr, b.hex(), flag))
    try:
        print('  %-24s %r' % ('', b.decode('latin-1')))
    except Exception:
        pass


def main():
    print('=' * 78)
    print('[1] 大整数进制解码（base62 / base36），字母表顺序 6 种')
    print('=' * 78)
    for name, al in ALPHAS.items():
        for tag, s in (('fwd', S), ('rev', S[::-1])):
            b = bigdecode(s, al)
            show('b62-%s-%s' % (name, tag), b)

    print()
    print('[1b] base36（0-9A-Z）')
    al36 = '0123456789abcdefghijklmnopqrstuvwxyz'
    for tag, s in (('fwd', S), ('rev', S[::-1])):
        show('b36-%s' % tag, bigdecode(s.lower(), al36))

    print()
    print('=' * 78)
    print('[2] base64 6bit 位流 / 换表（仿射 a*x+b mod 64, a 与 64 互素）')
    print('=' * 78)
    B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    idx = [B64.index(c) for c in S]
    hits = []
    for a in range(1, 64, 2):
        for b in range(64):
            # 尝试把密文下标 idx 逆变换回标准下标: x = a^-1*(y-b)
            try:
                ainv = pow(a, -1, 64)
            except ValueError:
                continue
            plain_idx = [(ainv * (y - b)) % 64 for y in idx]
            bits = ''.join(format(x, '06b') for x in plain_idx)
            bits = bits[:len(bits) // 8 * 8]
            by = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
            pr = sum(1 for x in by if 32 <= x < 127) / len(by)
            if pr > 0.9:
                hits.append(('affine a=%d b=%d' % (a, b), by))
    for tag, by in hits[:20]:
        show(tag, by)
    print('  [INFO] affine 可打印命中 = %d' % len(hits))

    print()
    print('[3] 6bit 下标 XOR k（k=1..63）')
    hits = []
    for k in range(1, 64):
        plain_idx = [x ^ k for x in idx]
        bits = ''.join(format(x, '06b') for x in plain_idx)
        bits = bits[:len(bits) // 8 * 8]
        by = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
        pr = sum(1 for x in by if 32 <= x < 127) / len(by)
        if pr > 0.9:
            hits.append(('%02x' % k, by))
    for tag, by in hits[:10]:
        show('xor6bit-' + tag, by)
    print('  [INFO] xor6bit 可打印命中 = %d' % len(hits))

    print()
    print('[4] 原样 base64 解码的原始字节（对照）')
    t = S + '=' * (-len(S) % 4)
    show('b64-direct', base64.b64decode(t))

    print()
    print('=' * 78)
    print('[5] 分组换位：按 4 字符一组列换位（block = 4）')
    print('=' * 78)
    blocks = [S[i:i + 4] for i in range(0, len(S), 4)]
    # 4x4 转置（把整个串写成 4 行）
    n = len(S)
    for rows in (2, 3, 4):
        cols = (n + rows - 1) // rows
        padded = S.ljust(rows * cols, '#')
        # 按行填、按列读
        col_read = ''.join(padded[r * cols + c] for c in range(cols) for r in range(rows) if padded[r * cols + c] != '#')
        show('transpose-rows%d' % rows, b64safe(col_read))
        # 按列填、按行读
        row_read = ''.join(padded[c * rows + r] for r in range(rows) for c in range(cols) if padded[c * rows + r] != '#')
        show('transpose-cols%d' % rows, b64safe(row_read))


def b64safe(s):
    t = s + '=' * (-len(s) % 4)
    try:
        return base64.b64decode(t)
    except Exception:
        return b''


if __name__ == '__main__':
    main()
