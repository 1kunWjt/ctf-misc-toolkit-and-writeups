# -*- coding: utf-8 -*-
"""第03题 旁路一：检查图片本身是否藏了东西（LSB / Alpha / 通道平面）
如果尾部 38 字符只是"钥匙"或者干扰，flag 可能在像素里。
"""
import os
import zlib

import numpy as np
from PIL import Image

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
PNG = os.path.join(BASE, 'files', 'tempdir', 'MISC附件', 'out.png')


def entropy(bits):
    """比特流的 0/1 比例，越接近 0.5 越像随机数据"""
    return bits.mean() if len(bits) else 0.0


def main():
    im = Image.open(PNG)
    print('[INFO] mode=%s size=%s' % (im.mode, im.size))
    a = np.array(im.convert('RGBA'))
    print('[INFO] alpha unique = %s' % np.unique(a[:, :, 3])[:10])

    for ci, cn in enumerate('RGBA'):
        ch = a[:, :, ci].astype(np.uint8)
        lsb = (ch & 1).ravel()
        print('[LSB] %s channel: ones ratio = %.4f' % (cn, lsb.mean()))

    # 把 RGBA 的 LSB 全部拼起来，看开头像不像有结构的文本
    for order in ('RGBA', 'RGB'):
        planes = [a[:, :, i] & 1 for i in range(4 if order == 'RGBA' else 3)]
        bits = np.stack(planes, axis=2).ravel()  # 交错：像素内按通道顺序
        bits = bits[:len(bits) // 8 * 8].astype(np.uint8)
        by = np.packbits(bits).tobytes()
        head = by[:64]
        pr = sum(1 for x in head if 32 <= x < 127) / len(head)
        print('[LSB-%s] head printable ratio=%.2f  %r' % (order, pr, head))

    # 单独的 alpha LSB 视图（把它当二值图看看有没有字）
    alpha_lsb = ((a[:, :, 3] & 1) * 255).astype(np.uint8)
    out = os.path.join(BASE, 'img', '_dbg_alpha_lsb.png')
    Image.fromarray(alpha_lsb).save(out)
    print('[OK] alpha LSB view -> %s' % out)

    # 蓝色通道 LSB 视图
    for ci, cn in enumerate('RGBA'):
        v = ((a[:, :, ci] & 1) * 255).astype(np.uint8)
        Image.fromarray(v).save(os.path.join(BASE, 'img', '_dbg_lsb_%s.png' % cn.lower()))
    print('[OK] channel LSB views saved')

    # 逐通道做高位/低位平面统计，找"最不像自然图"的平面
    for ci, cn in enumerate('RGBA'):
        for b in range(8):
            plane = (a[:, :, ci] >> b) & 1
            r = plane.mean()
            if 0.45 < r < 0.55:
                print('  [PLANE] %s bit%d ratio=%.3f (随机带)' % (cn, b, r))


if __name__ == '__main__':
    main()
