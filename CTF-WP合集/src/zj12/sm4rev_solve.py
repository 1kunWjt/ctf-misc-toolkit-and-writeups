# -*- coding: utf-8 -*-
"""第 12 题 sm4rev —— SM4 解密还原 flag。

常量来源（都在载荷 sm4_rev 的 .rodata 里，VA 与文件偏移一一对应，非 PIE 基址 0x400000）：
  0x57a040  S 盒 256 字节（国标 GB/T 32907-2016 标准 S 盒）
  0x57a140  写死的 T 表（256 × 4 字节）
密文与密钥来自 checker（0x404cb0）用 movabs 直接压栈的立即数：
  key    = 0x0123456789abcdeffedcba9876543210
  密文    = 48 字节 → 43 字节 flag + PKCS#7 的 5 个 0x05
"""

SBOX = bytes.fromhex(
    'd690e9fecce13db716b614c228fb2c052b679a762abe04c3aa44132649860699'
    '9c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa6'
    '4707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35'
    '1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89e'
    'eabf8ad240c738b5a3f7f2cef96115a1e0ae5da49b341a55ad933230f58cb1e3'
    '1df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51'
    '8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b0'
    '8969974a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3ed7cb3948'
)
FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
CK = [((4 * i) * 7 % 256) << 24 | ((4 * i + 1) * 7 % 256) << 16 |
      ((4 * i + 2) * 7 % 256) << 8 | ((4 * i + 3) * 7 % 256) for i in range(32)]
M = 0xFFFFFFFF


def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & M


def tau(a):
    return (SBOX[a >> 24] << 24 | SBOX[(a >> 16) & 0xFF] << 16 |
            SBOX[(a >> 8) & 0xFF] << 8 | SBOX[a & 0xFF])


def T(a):
    b = tau(a)
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)


def Tp(a):
    b = tau(a)
    return b ^ rotl(b, 13) ^ rotl(b, 23)


def key_schedule(key):
    mk = [int.from_bytes(key[4 * i:4 * i + 4], 'big') for i in range(4)]
    k = [mk[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        rk.append(k[i] ^ Tp(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]))
        k.append(rk[-1])
    return rk


def crypt_block(block, rk):
    x = [int.from_bytes(block[4 * i:4 * i + 4], 'big') for i in range(4)]
    for i in range(32):
        x.append(x[i] ^ T(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]))
    return b''.join(v.to_bytes(4, 'big') for v in (x[35], x[34], x[33], x[32]))


def selftest():
    """GB/T 32907-2016 附录 A 标准向量"""
    key = bytes.fromhex('0123456789abcdeffedcba9876543210')
    pt = bytes.fromhex('0123456789abcdeffedcba9876543210')
    want = bytes.fromhex('681edf34d206965e86b3e94f536e4246')
    got = crypt_block(pt, key_schedule(key))
    print('[i] 国标测试向量 =', got.hex(), ' 期望 =', want.hex(), ' 一致 =', got == want)
    return got == want


KEY = bytes.fromhex('0123456789abcdeffedcba9876543210')
CT = bytes.fromhex('825dad7df74bde01dc9e6a43066c454f'
                   '850d696d4e9184654222d8b032c5ab2d'
                   '83d3a869835b203e3abc5e12243735bf')

if not selftest():
    raise SystemExit('SM4 实现与国标不符，先修实现')

rk_enc = key_schedule(KEY)
rk_dec = rk_enc[::-1]
pt = b''.join(crypt_block(CT[i:i + 16], rk_dec) for i in range(0, len(CT), 16))
print('[*] 解密结果 =', pt)
print('[OK] 去掉 PKCS#7 填充 =', pt[:-pt[-1]].decode())
rt = b''.join(crypt_block(pt[i:i + 16], rk_enc) for i in range(0, len(pt), 16))
print('[i] 再加密一遍 == 原密文 ?', rt == CT)
