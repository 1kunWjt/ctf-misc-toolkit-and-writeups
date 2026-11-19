# -*- coding: utf-8 -*-
"""
solve_09.py —— 第 09 题 ezRe 求解

反汇编（pyc39.py）读出来的结构：
    import base64
    text = input('Flag: ')
    key  = '7e021a7dd49e4bd0837e22129682551b'
    key = [ord(i) ^ 102 for i in key]          # listcomp: 常量 102
    s = list(range(256)); j = 0
    for i in range(256):                        # RC4 KSA
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    data = []
    for _ in range(50):                         # RC4 PRGA，取 50 字节密钥流
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        data.append(s[(s[i] + s[j]) % 256])
    result = ''
    for c, k in zip(text, data):
        result += chr(ord(c) ^ k ^ 51)          # 常量 51
    enc = base64.b64encode(result.encode()).decode()
    if enc == '<常量>': print('yes!') else print('try again...')

所以解密 = 反过来：base64decode → utf-8 decode → latin-1 拿回原字节 → 异或 keystream 和 51。
"""
import base64

CIPHER = 'w53Cj3HDgzTCsSM5wrg6FMKcw58Qw7RZSFLCljRxwrxbwrVdw4AEwqMjw7/DkMKTw4/Cv8Onw4NGw7jDmSdcwq4GGg=='
KEYHEX = '7e021a7dd49e4bd0837e22129682551b'
KXOR = 102
CXOR = 51
N = 50


def keystream(n=N):
    key = [ord(c) ^ KXOR for c in KEYHEX]
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    out = []
    i = j = 0
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) % 256])
    return out


def recover():
    raw = base64.b64decode(CIPHER)
    # 原程序把 chr(码点) 拼成字符串再 .encode()（UTF-8），所以每个原始字节变成了 1~2 个 UTF-8 字节
    text = raw.decode('utf-8')
    latin = text.encode('latin-1')      # 拿回"每个字符一个字节"的原始形态
    ks = keystream()
    flag = ''.join(chr(latin[i] ^ ks[i] ^ CXOR) for i in range(min(len(latin), len(ks))))
    return raw, text, latin, ks, flag


def forward(flag):
    """复现原程序：用于自证（正着算一遍应等于原常量）"""
    ks = keystream()
    result = ''.join(chr(ord(flag[i]) ^ ks[i] ^ CXOR) for i in range(len(flag)))
    return base64.b64encode(result.encode()).decode()


if __name__ == '__main__':
    raw, text, latin, ks, flag = recover()
    print('[1] base64 解码 = %d 字节' % len(raw))
    print('[2] UTF-8 解码得到 %d 个字符（说明原程序 chr() 的码点 >127）' % len(text))
    print('[3] 还原成原始字节 = %d 字节' % len(latin))
    print('[4] 前 12 字节密钥流 =', ' '.join('%02x' % x for x in ks[:12]))
    print('[5] 明文 = %r' % flag)
    print()
    ok = forward(flag) == CIPHER
    print('[校验] 正着再编码一遍 == 题目给的常量 ? %s' % ('YES' if ok else 'NO'))
    if flag.startswith('DASCTF'):
        print('[FLAG]', flag)
