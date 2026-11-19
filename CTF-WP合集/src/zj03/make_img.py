# -*- coding: utf-8 -*-
"""第03题 配图生成：把 solve/*.py 的真实 stdout 渲染成 PNG（不编造输出）"""
import io
import os
import sys
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(os.path.join(HERE, '..'))
sys.path.insert(0, os.path.join(BASE, '..', '..', '_wp'))
sys.path.insert(0, HERE)

from imgkit import flow, hexdump, flagbox, term  # noqa: E402

IMG = os.path.join(BASE, 'img')
os.makedirs(IMG, exist_ok=True)


def run(modname, func='main'):
    """执行脚本并抓真实 stdout"""
    buf = io.StringIO()
    mod = __import__(modname)
    with redirect_stdout(buf):
        getattr(mod, func)()
    return [ln for ln in buf.getvalue().replace('\r', '').split('\n')]


def colored(lines):
    """给关键行上色，方便读者扫读"""
    out = []
    for ln in lines:
        if ln.startswith('[OK]') or '[FLAG]' in ln or ln.startswith('[HIT]'):
            out.append((ln, (78, 201, 118)))
        elif ln.startswith('[FAIL]') or ln.startswith('[INFO]'):
            out.append((ln, (86, 182, 194)))
        elif 'FLAG' in ln:
            out.append((ln, (229, 192, 123)))
        else:
            out.append((ln, (220, 220, 220)))
    return out


def main():
    # 01 流程图
    flow([
        ('体检 PNG 结构', 'chunk 走一遍，IEND 后还剩 38 字节'),
        ('盯住尾巴', 'base64 字符集，但直接解是乱码'),
        ('怀疑换表', '换表题必须找到那张 64 字符的表'),
        ('LSB 抽表', 'R,G,B 最低位拼字节 -> 64 字符码表'),
        ('换表 + 解码', 'tail.translate(custom->std) -> b64decode'),
        ('得到 flag', 'DASCTF{We1C0me_2_ZJCTF2024!}'),
    ], os.path.join(IMG, '01-flow.png'), title='RealSignin 解题链路')

    # 02 结构体检的真实输出
    lines = run('step1_inspect')
    term(colored(lines), os.path.join(IMG, '02-inspect.png'),
         title='step1_inspect.py  (PNG chunk walk + tail)')

    # 03 LSB 抽表 + 换表解码的真实输出
    lines = run('step5_solve')
    term(colored(lines), os.path.join(IMG, '03-lsb-table.png'),
         title='step5_solve.py  (LSB table -> translate -> decode)')

    # 04 尾部 38 字节的十六进制视图（真实数据）
    tail = open(os.path.join(HERE, '_tail.bin'), 'rb').read()
    hexdump(tail, os.path.join(IMG, '04-tail-hexdump.png'), max_rows=6,
            title='tail after IEND (38 bytes)')

    # 05 flag 放大
    flagbox('DASCTF{We1C0me_2_ZJCTF2024!}', os.path.join(IMG, '05-flag.png'))
    print('[OK] 配图生成完成')
    for f in sorted(os.listdir(IMG)):
        print('   img/%s  %d bytes' % (f, os.path.getsize(os.path.join(IMG, f))))


if __name__ == '__main__':
    main()
