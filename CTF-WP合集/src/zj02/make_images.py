# -*- coding: utf-8 -*-
"""生成 WP-02 的配图（全部来自真实文件/真实运行）"""
import base64
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WP = os.path.dirname(HERE)
FILES = os.path.join(WP, 'files')
sys.path.insert(0, os.path.join(WP, '..', '..', '_wp'))
from imgkit import term, flow, flagbox, hexdump  # noqa: E402

IMG = os.path.join(WP, 'img')
os.makedirs(IMG, exist_ok=True)

# ---------------------------------------------------------------- 1. 目录结构（真实）
rows = []
rows.append('PS> Get-ChildItem -Recurse files | select Name,Length')
rows.append('')
rows.append('%-34s %9s' % ('Name', 'Length'))
rows.append('%-34s %9s' % ('----', '------'))
for dp, dn, fn in os.walk(FILES):
    for f in sorted(fn):
        p = os.path.join(dp, f)
        rel = os.path.relpath(p, FILES)
        rows.append('%-34s %9d' % (rel, os.path.getsize(p)))
rows += ['', '[!] 没有 .php / .py / .jsp / .sql —— 没有后端',
         '[!] 没有 api 目录 —— 没有接口', '[OK] 结论：纯前端单页应用，数据全在 JS 里']
term(rows, os.path.join(IMG, '02-static-site.png'), title='附件结构（真实）')

# ---------------------------------------------------------------- 2. 在 bundle 里搜 DASCTF
js = os.path.join(FILES, 'assets', 'index-db9ab39a.js')
t = open(js, encoding='utf-8', errors='ignore').read()
idx = t.find('DASCTF')
snippet = t[max(0, idx - 210):idx + 120]

rows = ['PS> python -c "t=open(r\'assets\\index-db9ab39a.js\').read(); i=t.find(\'DASCTF\'); print(len(t), i)"',
        '%d %d' % (len(t), idx),
        '',
        'PS> # 把命中位置前后 300 字符打出来',
        '...' + snippet[:78],
        snippet[78:160],
        snippet[160:] + '...'
]
term(rows, os.path.join(IMG, '03-search.png'), title='搜 DASCTF 命中位置（真实）')

# ---------------------------------------------------------------- 3. 拼密文 + 认 Salted__
C = {
    "p7": "U2Fs", "p3": "dGVk", "p11": "X1+x", "p2": "gQkA", "p9": "1DNc", "p4": "IT2l",
    "p1": "hj0T", "p8": "gq4g", "p13": "v905", "p6": "V00l", "p10": "ejoT", "p5": "vugY",
    "p15": "8hIu", "p12": "AS+e", "p14": "wfn0", "p16": "/J8V", "p19": "wJ7n", "p17": "/4IX",
    "p20": "rZUp", "p18": "5h+8", "p21": "y6wX", "p22": "Rg==",
}
ORDER = ["p7", "p3", "p11", "p2", "p9", "p4", "p1", "p8", "p13", "p6", "p10", "p5",
         "p15", "p12", "p14", "p16", "p19", "p17", "p20", "p18", "p21", "p22"]
blob = ''.join(C[k] for k in ORDER)
raw = base64.b64decode(blob)
open(os.path.join(HERE, 'blob.txt'), 'w', encoding='utf-8').write(blob)

hexdump(raw[:48], os.path.join(IMG, '04-salted.png'),
        title='base64 解码后的前 48 字节（真实）', max_rows=3)

# ---------------------------------------------------------------- 4. node 解密输出（读真实 stdout）
out_txt = os.path.join(HERE, 'node_output.txt')
if os.path.exists(out_txt):
    lines = [l.rstrip() for l in open(out_txt, encoding='utf-8').read().splitlines()]
    lines = [l for l in lines if l.strip()]
    term(['PS> node ..\\..\\..\\真题模拟\\解签到题2-网安知识大挑战.js'] + lines,
         os.path.join(IMG, '05-decrypt.png'), title='node 解密（真实输出）')

# ---------------------------------------------------------------- 5. 流程图
flow([
    ('看目录结构', '没有 .php / 没有接口 → 纯前端题，数据在 JS 里'),
    ('在 bundle 里搜特征词', '搜 DASCTF → 命中 1,115,975 偏移处的解密函数'),
    ('抠出密文碎片', '22 个 p1~p22 按数组顺序拼接，p23 是诱饵不参与'),
    ('认出格式', 'Base64 解出来是 "Salted__" → CryptoJS / OpenSSL 格式'),
    ('密钥派生', '口令 + salt 走 MD5 版 EVP KDF（不是 PBKDF2）'),
    ('AES-256-CBC 解密', '模式错写成 ECB 就全是乱码'),
    ('拿到 flag', 'DASCTF{N3tw0rk_S3cur1ty_1s_1mp0rt4nt}'),
], os.path.join(IMG, '01-flow.png'), title='第 2 题：前端题的标准打法')

flagbox('DASCTF{N3tw0rk_S3cur1ty_1s_1mp0rt4nt}', os.path.join(IMG, '06-flag.png'))
print('[OK] images ->', IMG)
print('blob len', len(blob), 'raw len', len(raw))
