# -*- coding: utf-8 -*-
"""
decode.py —— 签到题自动剥皮器（比赛时直接拿来用）

用法：
    python decode.py "271 个字符的密文"
    python decode.py -f cipher.txt

原理：
    每一层都试一遍，只看"解出来是不是几乎全可打印"。
    可打印率 > 98% 就认为是这一层对了（随机二进制几乎不可能全可打印）。
    这个判据比"猜字母表"可靠得多。
"""
import sys
from base_codec import DECODERS, printable_ratio


def show(s, n=72):
    s = s.replace('\n', '\\n')
    return s if len(s) <= n else s[:n] + '...'


def peel_verbose(text, max_layer=12):
    cur = text
    layers = []
    print('输入: %d 字符' % len(cur))
    for layer in range(1, max_layer + 1):
        print('\n---- 第 %d 层 ----' % layer)
        cands = []
        for name, fn in DECODERS:
            try:
                out = fn(cur)
            except Exception as e:
                print('  %-7s 失败 (%s)' % (name, type(e).__name__))
                continue
            r = printable_ratio(out)
            print('  %-7s -> %4d 字节, 可打印 %5.1f%%  %s' % (name, len(out), r * 100, show(out.decode('utf-8', 'replace'), 46)))
            if r > 0.98:
                cands.append((r, name, out))
        if not cands:
            print('\n[STOP] 没有可打印的候选，链条到此为止')
            break
        cands.sort(reverse=True)
        r, name, out = cands[0]
        layers.append((name, len(out)))
        print('  >> 采用 %s（可打印率 %.1f%%）' % (name, r * 100))
        cur = out.decode('utf-8', 'replace')
        if 'DASCTF{' in cur or 'flag{' in cur.lower() or 'ctf{' in cur.lower():
            print('\n[OK] 命中 flag：', cur)
            break
    print('\n==== 链路汇总 ====')
    total = len(text)
    print('输入 %d 字符' % total)
    for name, n in layers:
        print('  --%-7s--> %d' % (name, n))
    print('\n最终明文：', cur)
    return cur


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    if sys.argv[1] == '-f':
        text = open(sys.argv[2], encoding='utf-8').read().strip()
    else:
        text = sys.argv[1].strip()
    peel_verbose(text)
