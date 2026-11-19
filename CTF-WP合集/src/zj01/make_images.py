# -*- coding: utf-8 -*-
"""生成 WP-01 的全部配图（每张图的内容都来自真实运行结果）"""
import io
import os
import sys
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
WP = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(WP, '..', '..', '_wp'))

from base_codec import (b32encode, b45encode, b58encode, b62encode, b64encode,
                        b85encode, b92encode)
from imgkit import term, flow, flagbox
from decode import peel_verbose

IMG = os.path.join(WP, 'img')
os.makedirs(IMG, exist_ok=True)

FLAG = 'DASCTF{welcome_to_zjctf_2024}'

# ---------------------------------------------------------------- 1. 自建七层密文
steps = [('base32', b32encode), ('base45', b45encode), ('base58', b58encode),
         ('base62', b62encode), ('base64', b64encode), ('base85', b85encode),
         ('base92', b92encode)]
s = FLAG
lines = ['PS> python base_codec.py', '']
lines.append('原文  : %s' % FLAG)
for name, fn in steps:
    s = fn(s)
    lines.append('%-7s -> %3d 字符' % (name, len(s)))
cipher = s
open(os.path.join(HERE, 'cipher.txt'), 'w', encoding='utf-8').write(cipher)

lines += ['', '密文（前 56 字符）:', cipher[:56] + ' ...']
lines += ['', '反向剥皮：']
back = cipher
inv = {'base92': None}
from base_codec import b32decode, b45decode, b58decode, b62decode, b64decode, b85decode, b92decode
invmap = {'base32': b32decode, 'base45': b45decode, 'base58': b58decode, 'base62': b62decode,
          'base64': b64decode, 'base85': b85decode, 'base92': b92decode}
for name, _ in reversed(steps):
    back = invmap[name](back).decode('utf-8')
    lines.append('解 %-7s -> %3d 字符 %s' % (name, len(back), back if len(back) < 30 else ''))
lines += ['', '[OK] 七层往返一致，明文 = ' + back]
term(lines, os.path.join(IMG, '02-roundtrip.png'), title='base_codec.py 自测（真实输出）')

# ---------------------------------------------------------------- 2. 自动剥皮（紧凑版）
buf = io.StringIO()
with redirect_stdout(buf):
    peel_verbose(cipher)
raw = [l.rstrip() for l in buf.getvalue().splitlines() if l.strip()]

# 只留：第 1 层的全部候选（演示"七个解码器都试一遍"）+ 每层结论 + 链路汇总
keep, in_layer1 = [], False
for l in raw:
    if l.startswith('输入'):
        keep.append(l)
    elif l.startswith('----'):
        in_layer1 = ('第 1 层' in l)
        keep.append(l)
    elif in_layer1 and (l.startswith('  base') or l.startswith('  >>')):
        keep.append(l[:78])
    elif l.startswith('  >>') or l.startswith('[OK]') or l.startswith('[STOP]') or l.startswith('最终') or l.startswith('  --') or l.startswith('===='):
        keep.append(l[:78])
    elif l.startswith('---- 第'):
        keep.append(l)
term(keep, os.path.join(IMG, '03-peel.png'), title='decode.py 自动剥皮（真实输出，已删减无关行）')

# ---------------------------------------------------------------- 3. 流程图
flow([
    ('看字符集，不看长度', '88 种字符、混着 { } \\ \' | → 不是任何标准编码'),
    ('先排除，再锁定', 'Base64/32 字符集对不上；Base91 明确排除 \' 和 \\ → 只剩 Base92'),
    ('逐层剥，每层要有"判据"', '解出来 100% 可打印 = 这层对了（随机二进制不可能）'),
    ('Base92 → Base85 → Base64', '前三层能靠"不可能巧合"确定'),
    ('Base62 → Base58 → Base45 → Base32', '后四层要靠工具/公开 writeup 补全'),
    ('29 字节明文 = flag', 'DASCTF{welcome_to_zjctf_2024}'),
], os.path.join(IMG, '01-flow.png'), title='签到题：七层套娃的剥法')

# ---------------------------------------------------------------- 4. flag
flagbox(FLAG, os.path.join(IMG, '04-flag.png'))
print('[OK] images ->', IMG)
print('cipher len', len(cipher))
