# -*- coding: utf-8 -*-
"""把 obj4 内容流解压后，直接看文本算子与字符串。"""
import re, zlib

PDF = r"C:\Users\XiaoMibook\Documents\deepseek-harness\default-workspace\CTF-WP\14-ds-encode\files\tempdir\DS附件\ds-encode附件_unzip\个人信息数据规范文档.pdf"
OUT = r"D:\XiaoMibook\CTF学习\.wp_scratch\14"
data = open(PDF, 'rb').read()

def stream_of(num):
    m = re.search((r'(?<![0-9])' + str(num) + r'\s+0\s+obj\b(.*?)endobj').encode(), data, re.S)
    body = m.group(1)
    i = body.find(b'stream')
    dic = body[:i]
    j = i + 6
    if body[j:j + 2] == b'\r\n': j += 2
    elif body[j:j + 1] in (b'\n', b'\r'): j += 1
    k = body.rfind(b'endstream')
    return dic, body[j:k]

dic, raw = stream_of(4)
c = zlib.decompress(raw)
open(OUT + r"\obj4_content.txt", 'wb').write(c)
print("[obj4] %d bytes dict=%r" % (len(c), dic[:60]))
txt = c.decode('latin1')
print("[obj4] BT count=%d Tf count=%d Tj=%d TJ=%d Do=%d" % (
    txt.count('BT'), txt.count('Tf'), txt.count('Tj'), txt.count('TJ'), txt.count('Do')))

# 列出所有 Tf 使用的资源名
print("\n[fonts used]", sorted(set(re.findall(r'/([A-Za-z0-9]+)\s+[\d.]+\s+Tf', txt))))
# 列出所有图像 XObject 引用
print("[xobj used]", sorted(set(re.findall(r'/([A-Za-z0-9]+)\s+Do', txt))))
# 打印所有 (...) 字面量
print("\n[literal strings]")
for m in re.finditer(r'\(((?:\\.|[^()\\])*)\)', txt):
    s = m.group(1)
    if len(s.strip()) and not s.strip().startswith('AAAA'):
        print("  %r" % s[:90])
print("\n[hex strings]")
for m in re.finditer(r'<([0-9A-Fa-f]{4,})>', txt):
    h = m.group(1)
    print("  %s  (len %d)" % (h[:80], len(h) // 2))

# 全文件搜 ASCII 关键词
print("\n[keywords in whole pdf]")
for kw in [b'MD5', b'md5', b'SHA', b'sha', b'UTF-8', b'utf-8', b'CSV', b'csv', b'userid', b'idcard', b'phone', b'result']:
    idx = data.find(kw)
    print("  %-8r @ %s" % (kw, hex(idx) if idx >= 0 else 'not found'))
