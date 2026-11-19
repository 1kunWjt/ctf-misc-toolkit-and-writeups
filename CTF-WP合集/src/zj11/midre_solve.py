# -*- coding: utf-8 -*-
"""第 11 题 Midre —— 还原 serial。

exe 里的算法链（静态逆出来的常量都在 .data）：
  1) scanf("%32s", buf)                → 32 字节以内的输入
  2) buf[i] ^= "what's this"[i % 11]    → 0x41e048，主函数里的滚动 XOR，i < 0x20
  3) 零填充到 16 的倍数                → 0x414750，len%16==0 时原样
  4) AES-128-CBC                        → key 0x41e000，IV = 0x41e024（每轮 IV 换成上一块密文）
  5) memcmp(密文, 0x41e06c, 0x20)       → 32 字节目标密文

所以反推：serial = CBC-dec(目标密文) ^ "what's this"
"""
import sys

SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d83115'
    '04c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f84'
    '53d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d1973'
    '60814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479'
    'e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a'
    '703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df'
    '8ca1890dbfe6426841992d0fb054bb16'
)
INV = [0] * 256
for _i, _v in enumerate(SBOX):
    INV[_v] = _i
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def xtime(a):
    a <<= 1
    return (a ^ 0x11b) & 0xFF if a & 0x100 else a


def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a = xtime(a)
    return r


def expand_key(key):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]


def encrypt_block(block, rks):
    s = [a ^ b for a, b in zip(block, rks[0])]
    for r in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]      # ShiftRows
        if r != 10:                                             # MixColumns
            ns = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                ns += [gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3,
                       a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3,
                       a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3),
                       gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)]
            s = ns
        s = [a ^ b for a, b in zip(s, rks[r])]
    return bytes(s)


def decrypt_block(block, rks):
    s = [a ^ b for a, b in zip(block, rks[10])]
    for r in range(9, -1, -1):
        s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]      # InvShiftRows
        s = [INV[b] for b in s]
        s = [a ^ b for a, b in zip(s, rks[r])]
        if r != 0:
            ns = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                ns += [gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9),
                       gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13),
                       gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11),
                       gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)]
            s = ns
    return bytes(s)


def selftest():
    rk = expand_key(bytes.fromhex('000102030405060708090a0b0c0d0e0f'))
    pt = bytes.fromhex('00112233445566778899aabbccddeeff')
    ct = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    ok1 = encrypt_block(pt, rk) == ct
    ok2 = decrypt_block(ct, rk) == pt
    print('[i] FIPS-197 C.1 加密自检 =', ok1, '/ 解密自检 =', ok2)
    return ok1 and ok2


AES_KEY = b'5855eab53a2275d3'      # .data 0x41e000，init(ptr, 0x80) → AES-128
CBC_IV = b'b051a57d6d05b393'       # .data 0x41e024，CBC 的 IV（t 变量每轮被换成上一块密文）
XORKEY = b"what's this"            # .data 0x41e048，主函数里 11 字节滚动 XOR
CT = bytes.fromhex('5206c49d28712604ba984d2003813939'
                   '8c6e148c7ebf445a67f50a7f617fce72')   # .data 0x41e06c

if not selftest():
    sys.exit(1)

rk = expand_key(AES_KEY)
pt, prev = b'', CBC_IV
for i in range(0, len(CT), 16):
    blk = CT[i:i + 16]
    pt += bytes(a ^ b for a, b in zip(decrypt_block(blk, rk), prev))
    prev = blk
print('[*] CBC 解密结果 =', pt.hex())

serial = bytes(pt[i] ^ XORKEY[i % 11] for i in range(32))
print('[OK] serial =', serial.decode('latin-1'))

# 正向自检：serial → XOR → CBC 加密，应当还原出目标密文
rin, prev, out = serial, CBC_IV, b''
rin = bytes(serial[i] ^ XORKEY[i % 11] for i in range(32))
for i in range(0, 32, 16):
    prev = encrypt_block(bytes(a ^ b for a, b in zip(rin[i:i + 16], prev)), rk)
    out += prev
print('[i] 正向重算 == 目标密文 ?', out == CT)
