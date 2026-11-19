# -*- coding: utf-8 -*-
"""
base_codec.py —— 七种 Base 编码的纯 Python 实现（无第三方依赖）

为什么要有这个文件：
    2024 省赛签到题是「Base92→Base85→Base64→Base62→Base58→Base45→Base32」七层套娃。
    现成工具（CyberChef）对 base92/62/58/45 支持不全，所以要自己有一套能用的编解码器。
    这套实现只用标准库，可以直接拿去当比赛工具包。

约定：
    - 所有 encode 输入 bytes / str（str 按 utf-8 编码），输出 str
    - 所有 decode 输入 str，输出 bytes
    - 每一层的"字母表"都写在 ALPHABET 里，看清楚字母表 = 看清楚这一层是什么编码
"""
import base64

# ---------------------------------------------------------------- 字母表

# Base92：ASCII 0x21~0x7D 去掉双引号，共 92 个字符（标准 base92 字母表）
B92 = ''.join(chr(i) for i in range(33, 126) if i != 34)

# Base62：最常见的 "数字+大写+小写" 顺序（不同实现会换表，这是坑）
B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

# Base58：Bitcoin 字母表，故意去掉了 0 O I l 这四个易混字符
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# Base45：RFC 9285（二维码里常见），含空格和 4 个符号
B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'

ALPHABET = {
    'base92': B92,
    'base62': B62,
    'base58': B58,
    'base45': B45,
    'base64': 'A-Za-z0-9+/=',
    'base32': 'A-Z2-7=',
    'base85': 'ASCII 85',
}


def _to_bytes(v):
    if isinstance(v, str):
        return v.encode('utf-8')
    return bytes(v)


# ---------------------------------------------------------------- 通用大整数进制

def _int_to_base(n, alphabet):
    """把整数按 alphabet 转成字符串；长度 1 表示 0"""
    b = len(alphabet)
    if n == 0:
        return alphabet[0]
    out = []
    while n:
        n, r = divmod(n, b)
        out.append(alphabet[r])
    return ''.join(reversed(out))


def _base_to_int(s, alphabet):
    b = len(alphabet)
    n = 0
    for ch in s:
        n = n * b + alphabet.index(ch)
    return n


# ---------------------------------------------------------------- Base92

def b92encode(data):
    """按整数进制转换（整串当作一个 256 进制大数）"""
    data = _to_bytes(data)
    if not data:
        return ''
    # 记录前导 0x00：它们在大整数里会消失，用 '!'（alphabet[0]）补回来
    n_lead = len(data) - len(data.lstrip(b'\x00'))
    s = _int_to_base(int.from_bytes(data, 'big'), B92)
    return B92[0] * n_lead + s


def b92decode(s):
    n_lead = len(s) - len(s.lstrip(B92[0]))
    n = _base_to_int(s, B92)
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    return b'\x00' * n_lead + raw


# ---------------------------------------------------------------- Base85 / Ascii85

def b85encode(data):
    data = _to_bytes(data)
    return base64.a85encode(data, adobe=False).decode()


def b85decode(s):
    s = s.strip()
    pad = (-len(s)) % 4
    return base64.a85decode(s + ('u' * 0 if pad == 0 else ''), adobe=False)


# ---------------------------------------------------------------- Base64 / 32

def b64encode(data):
    return base64.b64encode(_to_bytes(data)).decode()


def b64decode(s):
    return base64.b64decode(s + '=' * ((-len(s)) % 4))


def b32encode(data):
    return base64.b32encode(_to_bytes(data)).decode()


def b32decode(s):
    return base64.b32decode(s + '=' * ((-len(s)) % 8))


# ---------------------------------------------------------------- Base62

def b62encode(data):
    data = _to_bytes(data)
    if not data:
        return ''
    n_lead = len(data) - len(data.lstrip(b'\x00'))
    return B62[0] * n_lead + _int_to_base(int.from_bytes(data, 'big'), B62)


def b62decode(s):
    n_lead = len(s) - len(s.lstrip(B62[0]))
    n = _base_to_int(s, B62)
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    return b'\x00' * n_lead + raw


# ---------------------------------------------------------------- Base58

def b58encode(data):
    data = _to_bytes(data)
    if not data:
        return ''
    n_lead = len(data) - len(data.lstrip(b'\x00'))
    return B58[0] * n_lead + _int_to_base(int.from_bytes(data, 'big'), B58)


def b58decode(s):
    n_lead = len(s) - len(s.lstrip(B58[0]))
    n = _base_to_int(s, B58)
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    return b'\x00' * n_lead + raw


# ---------------------------------------------------------------- Base45

def b45encode(data):
    data = _to_bytes(data)
    out = []
    for i in range(0, len(data) - 1, 2):
        x = data[i] * 256 + data[i + 1]
        c = x % 45
        x //= 45
        d = x % 45
        x //= 45
        assert x < 45
        out.append(B45[c] + B45[d] + B45[x])
    if len(data) % 2:
        x = data[-1]
        c = x % 45
        x //= 45
        assert x < 45
        out.append(B45[c] + B45[x])
    return ''.join(out)


def b45decode(s):
    out = bytearray()
    i = 0
    while i < len(s):
        if i + 3 <= len(s):
            a, b, c = (B45.index(s[i]), B45.index(s[i + 1]), B45.index(s[i + 2]))
            x = a + b * 45 + c * 45 * 45
            assert x < 65536, 'base45 长度或字母表不对'
            out += bytes([x // 256, x % 256])
            i += 3
        else:
            a, b = B45.index(s[i]), B45.index(s[i + 1])
            x = a + b * 45
            assert x < 256
            out.append(x)
            i += 2
    return bytes(out)


# ---------------------------------------------------------------- 自动剥皮

DECODERS = [
    ('base92', b92decode),
    ('base85', b85decode),
    ('base64', b64decode),
    ('base62', b62decode),
    ('base58', b58decode),
    ('base45', b45decode),
    ('base32', b32decode),
]


def printable_ratio(b):
    if not b:
        return 0.0
    ok = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return ok / len(b)


def peel(text, verbose=True):
    """自动循环剥皮：只要某一层解出来"几乎全是可打印字符"就认为这层对了"""
    cur = text
    history = [(len(cur), '输入')]
    while True:
        best = None
        for name, fn in DECODERS:
            try:
                out = fn(cur)
            except Exception:
                continue
            r = printable_ratio(out)
            if verbose:
                print('  try %-7s -> %4d bytes, printable %.0f%%' % (name, len(out), r * 100))
            if r > 0.98 and out != (cur.encode() if isinstance(cur, str) else cur):
                if best is None or r > best[2]:
                    best = (name, out, r)
        if not best:
            break
        name, out, r = best
        history.append((len(out), name))
        if verbose:
            print('>> 命中 %s，输出 %d 字节' % (name, len(out)))
        cur = out.decode('utf-8', 'replace')
        if 'DASCTF{' in cur or 'flag{' in cur.lower():
            break
    return cur, history


if __name__ == '__main__':
    flag = 'DASCTF{welcome_to_zjctf_2024}'
    s = flag
    chain = [('base32', b32encode), ('base45', b45encode), ('base58', b58encode),
             ('base62', b62encode), ('base64', b64encode), ('base85', b85encode),
             ('base92', b92encode)]
    for name, fn in chain:
        s = fn(s)
        print('%-7s -> %3d 字符' % (name, len(s)))
    print('密文:', s[:60], '...' if len(s) > 60 else '')
    print()
    back = s
    for name, fn in reversed(chain):
        back = {'base32': b32decode, 'base45': b45decode, 'base58': b58decode,
                'base62': b62decode, 'base64': b64decode, 'base85': b85decode,
                'base92': b92decode}[name](back).decode('utf-8', 'replace')
        print('%-7s -> %3d 字符  %s' % ('解 ' + name, len(back), back if len(back) < 40 else ''))
    assert back == flag, back
    print('\n[OK] 七层往返一致：', back)
