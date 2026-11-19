# -*- coding: utf-8 -*-
"""第03题 第四步：真正解出来
关键突破：图片像素 LSB（R,G,B 交错）的前 64 个字节 = 一张 64 字符的自定义 base64 码表
          ABCDEFGHIJKLMNabcdefghijklmnopqrstuvwxyzOPQRSTUVWXYZ0123456789+/
用这张表把尾部 38 字符换回标准码表再解码 -> flag
"""
import base64
import os

import numpy as np
from PIL import Image

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
PNG = os.path.join(BASE, 'files', 'tempdir', 'MISC附件', 'out.png')
TAIL = 'dEFfc1dGq1pxMgMWnihrMx9mewNgdvIWMvctrc'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def extract_lsb_table(path, n=64):
    """按 像素(行优先) -> R,G,B 的顺序取最低位，8 位拼一个字节"""
    a = np.array(Image.open(path).convert('RGB'))
    h, w, _ = a.shape
    bits = []
    for y in range(h):
        for x in range(w):
            for c in range(3):
                bits.append(int(a[y, x, c]) & 1)
                if len(bits) >= n * 8:
                    return bytes(int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, n * 8, 8))
    return b''


def main():
    table = extract_lsb_table(PNG, 64)
    print('[OK] LSB 前 64 字节 = %r' % table)
    custom = table.decode('latin-1')
    assert len(custom) == 64, 'table length != 64'
    assert sorted(custom) == sorted(STD), 'table is not a permutation of base64 alphabet'
    print('[OK] 是一张合法的 base64 码表（64 字符，正好是标准表的一个排列）')
    print('[INFO] 自定义表 = %s' % custom)

    # 找出这张表和标准表的差别：描述成"分段重排"
    print('[INFO] 自定义表分段: %s | %s | %s | %s'
          % (custom[0:14], custom[14:40], custom[40:52], custom[52:]))

    print()
    print('[INFO] 尾部 38 字符 = %s' % TAIL)
    std_form = TAIL.translate(str.maketrans(custom, STD))
    print('[INFO] 换回标准码表 = %s' % std_form)
    s = std_form + '=' * (-len(std_form) % 4)
    raw = base64.b64decode(s)
    print('[OK] b64decode -> %r  (%d bytes)' % (raw, len(raw)))
    try:
        print('[FLAG] %s' % raw.decode())
        open(os.path.join(BASE, 'solve', '_flag.txt'), 'w', encoding='utf-8').write(raw.decode())
    except UnicodeDecodeError:
        print('[FAIL] 不是合法 utf-8')

    # 对照：直接用标准表解（证明"必须换表"）
    try:
        wrong = base64.b64decode(TAIL + '==')
        print('[对照] 用标准表直接解 = %r  <- 乱码，说明换表是必需的' % wrong)
    except Exception as e:
        print('[对照] 标准表直接解异常: %s' % e)


if __name__ == '__main__':
    main()
