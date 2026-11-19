# -*- coding: utf-8 -*-
"""生成 WP-09 的配图（内容来自真实解析/真实运行）"""
import io
import os
import sys
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
WP = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(WP, '..', '..', '_wp'))

import pyc39 as P
from imgkit import term, flow, flagbox
import solve_09

IMG = os.path.join(WP, 'img')
os.makedirs(IMG, exist_ok=True)
PYC = os.path.join(WP, 'files', 'tempdir', 'REVERSE附件', 'ezRe')

# ---------------------------------------------------------------- 1. 文件头 + 结构
data = open(PYC, 'rb').read()
magic, top = P.parse_file(PYC)
rows = [
    'PS> python -c "print(open(r\'ezRe\',\'rb\').read()[:16].hex(\' \'))"',
    '%s' % ' '.join('%02x' % b for b in data[:16]),
    '',
    'PS> python pyc39.py ezRe',
    'magic = %s (3425 = Python 3.9)' % hex(magic),
    'len(co_code)  = %d' % len(top.code),
    'co_consts     = %d 个' % len(top.consts),
    'co_names      = %r' % (top.names[:12],),
    '             ... %d 个名字' % len(top.names),
    '',
    '内层 <listcomp>: consts=%r  varnames=%r' % (
        [c for c in top.consts if isinstance(c, P.Code)][0].consts,
        [c for c in top.consts if isinstance(c, P.Code)][0].varnames),
]
term(rows, os.path.join(IMG, '02-structure.png'), title='pyc 头部与结构（真实解析结果）')

# ---------------------------------------------------------------- 2. 反汇编片段
lines = open(os.path.join(HERE, '_dis_clean.txt'), encoding='utf-8').read().splitlines()
ksa = lines[36:70]
term(['PS> python pyc39.py ezRe   # 跳过 <JUNK 0x00> 之后的 KSA 循环：'] + ksa,
     os.path.join(IMG, '03-disasm-ksa.png'), title='反汇编 · RC4 初始化(KSA)')

prga = lines[135:178]
term(['PS> # PRGA 取密钥流 + 逐字符异或（注意 LOAD_CONST 51）'] + prga,
     os.path.join(IMG, '04-disasm-prga.png'), title='反汇编 · PRGA 与异或')

# ---------------------------------------------------------------- 3. 求解（真实运行）
buf = io.StringIO()
with redirect_stdout(buf):
    raw, text, latin, ks, flag = solve_09.recover()
    print('[1] base64 解码 = %d 字节' % len(raw))
    print('[2] UTF-8 解码得到 %d 个字符（chr 码点 >127，所以被编码两次）' % len(text))
    print('[3] 还原成原始字节 = %d 字节' % len(latin))
    print('[4] 密钥流前 12 字节 =', ' '.join('%02x' % x for x in ks[:12]))
    print('[5] 明文 = %s' % flag)
    print('')
    print('[校验] 正着再编码一遍 == 题给常量 ? %s' % ('YES' if solve_09.forward(flag) == solve_09.CIPHER else 'NO'))
term(['PS> python solve/solve_09.py'] + buf.getvalue().splitlines(),
     os.path.join(IMG, '05-solve.png'), title='solve_09.py 真实输出')

# ---------------------------------------------------------------- 4. 流程图
flow([
    ('看文件头', '61 0d 0d 0a = magic 3425 → Python 3.9 的 .pyc'),
    ('为什么不能直接跑', '本机是 3.12，marshal 读不了 3.9 的 code object'),
    ('手写 marshal 解析器', '按 CPython 3.9 marshal.c 逐类型读；关键坑是 FLAG_REF 要 pre-order 预留槽位'),
    ('反汇编', '按 3.9 opcode 表还原指令；发现大量 0x00 干扰字节，跳过'),
    ('读逻辑', '认出来是 RC4：KSA 256 轮 + PRGA 取 50 字节密钥流'),
    ('逆运算', 'base64decode → utf8 → latin-1 → 异或密钥流和 0x33'),
    ('验证', '把明文正着再编码一遍，必须等于题给常量 → YES'),
], os.path.join(IMG, '01-flow.png'), title='第 09 题 ezRe：从 pyc 到 flag')

flagbox(flag, os.path.join(IMG, '06-flag.png'))
print('[OK] images ->', IMG)
print('flag =', flag)
