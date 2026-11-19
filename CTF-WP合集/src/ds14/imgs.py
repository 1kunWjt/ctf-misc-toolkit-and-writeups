# -*- coding: utf-8 -*-
"""14-ds-encode：把 PDF 里的 Image XObject 抠成 PNG（只读附件，输出到 scratch）。"""
import os, re, zlib, sys
from PIL import Image

PDF = r"C:\Users\XiaoMibook\Documents\deepseek-harness\default-workspace\CTF-WP\14-ds-encode\files\tempdir\DS附件\ds-encode附件_unzip\个人信息数据规范文档.pdf"
OUT = r"D:\XiaoMibook\CTF学习\.wp_scratch\14\img"
os.makedirs(OUT, exist_ok=True)
data = open(PDF, 'rb').read()
print("[pdf] %d bytes" % len(data))

NCOMP = {b'/DeviceRGB': 3, b'/DeviceGray': 1, b'/DeviceCMYK': 4}
ICCBASED_N = {b'22': 3, b'27': 3, b'17': 3}

for m in re.finditer(rb'(\d+)\s+0\s+obj\s*<<(.*?)>>\s*stream\r?\n', data, re.S):
    num = m.group(1).decode()
    dic = m.group(2)
    if b'/Image' not in dic:
        continue
    w = int(re.search(rb'/Width\s+(\d+)', dic).group(1))
    h = int(re.search(rb'/Height\s+(\d+)', dic).group(1))
    bpc = int(re.search(rb'/BitsPerComponent\s+(\d+)', dic).group(1))
    cs = re.search(rb'/ColorSpace\s+(/[A-Za-z0-9]+|\d+\s+0\s+R)', dic)
    cs = cs.group(1) if cs else b''
    flt = re.search(rb'/Filter\s*(/\w+|\[\s*/\w+\s*/?\w*\s*\])', dic)
    smask = re.search(rb'/SMask\s+(\d+)\s+0\s+R', dic)
    ln = int(re.search(rb'/Length\s+(\d+)', dic).group(1))
    raw = data[m.end():m.end() + ln]
    print("\n[obj %s] %dx%d bpc=%d cs=%r filter=%r len=%d smask=%s" % (
        num, w, h, bpc, cs, flt.group(1) if flt else None, ln, smask.group(1).decode() if smask else '-'))
    if bpc != 8:
        print("   skip (bpc!=8)"); continue
    n = NCOMP.get(cs) or ICCBASED_N.get(cs.split()[0] if cs else b'')
    if n is None:
        print("   unknown colorspace -> assume 3"); n = 3
    try:
        px = zlib.decompress(raw)
    except Exception as e:
        print("   inflate FAIL %s" % e); continue
    need = w * h * n
    print("   inflated %d need %d" % (len(px), need))
    if len(px) < need:
        px = px + b'\x00' * (need - len(px))
    im = Image.frombytes({1: 'L', 3: 'RGB', 4: 'CMYK'}[n], (w, h), px[:need])
    if smask:
        sn = smask.group(1).decode()
        sm = re.search((r'(?<![0-9])' + sn + r'\s+0\s+obj\s*<<(.*?)>>\s*stream\r?\n').encode(), data, re.S)
        if sm:
            slen = int(re.search(rb'/Length\s+(\d+)', sm.group(1)).group(1))
            try:
                sa = zlib.decompress(data[sm.end():sm.end() + slen])
                if len(sa) >= w * h:
                    im.putalpha(Image.frombytes('L', (w, h), sa[:w * h]))
                    print("   smask applied")
            except Exception as e:
                print("   smask fail %s" % e)
    p = os.path.join(OUT, 'obj%s_%dx%d.png' % (num, w, h))
    im.save(p)
    print("   -> %s" % p)
