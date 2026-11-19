# -*- coding: utf-8 -*-
"""第03题 第一步：PNG 结构体检 —— 找出 IEND 之后的尾巴是什么"""
import os
import struct
import sys
import zlib

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
PNG = os.path.join(BASE, 'files', 'tempdir', 'MISC附件', 'out.png')


def main():
    data = open(PNG, 'rb').read()
    print('[INFO] file size = %d bytes' % len(data))
    print('[INFO] signature = %s' % data[:8].hex())

    # 逐块走 PNG：长度(4) 类型(4) 数据(n) CRC(4)
    off = 8
    chunks = []
    while off + 8 <= len(data):
        (ln,) = struct.unpack('>I', data[off:off + 4])
        typ = data[off + 4:off + 8].decode('latin-1')
        end = off + 8 + ln + 4
        chunks.append((off, typ, ln, end))
        print('  chunk %-4s off=%-7d len=%-7d end=%d' % (typ, off, ln, end))
        if typ == 'IEND':
            break
        off = end

    iend_off, iend_typ, iend_len, iend_end = chunks[-1]
    tail = data[iend_end:]
    print('[INFO] IEND ends at %d, trailing bytes = %d' % (iend_end, len(tail)))
    print('[TAIL hex] %s' % tail.hex())
    print('[TAIL repr] %r' % tail)

    # 只保留可见 ASCII 部分
    vis = bytes(b for b in tail if 32 <= b < 127)
    print('[TAIL ascii] len=%d  %s' % (len(vis), vis.decode()))
    open(os.path.join(BASE, 'solve', '_tail.bin'), 'wb').write(tail)

    # 顺便校验一下 IDAT 能不能解出来（证明图片本身是完整的）
    idat = b''.join(data[o + 8:o + 8 + l] for o, t, l, e in chunks if t == 'IDAT')
    raw = zlib.decompress(idat)
    w, h = struct.unpack('>II', data[16:24])
    print('[OK] IDAT decompressed = %d bytes, image %dx%d, bitdepth=%d colortype=%d'
          % (len(raw), w, h, data[24], data[25]))


if __name__ == '__main__':
    main()
