# -*- coding: utf-8 -*-
"""合集配图工具（Pillow 版）：画流程图 / 终端输出块。
只用等宽字体渲染 ASCII，保证对齐；中文用黑体。
"""
import os
from PIL import Image, ImageDraw, ImageFont

IMG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'img')
os.makedirs(IMG, exist_ok=True)

MONO = 'C:/Windows/Fonts/consola.ttf'
CN = 'C:/Windows/Fonts/msyh.ttc'


def _f(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


def flow(steps, out, title='flow', width=980):
    """steps: [(标题, 说明), ...] 竖排流程图"""
    fs_t, fs_c, fs_title = _f(CN, 22), _f(CN, 17), _f(CN, 26)
    boxh, gap, margin = 78, 34, 30
    h = margin * 2 + 52 + len(steps) * (boxh + gap)
    img = Image.new('RGB', (width, h), 'white')
    d = ImageDraw.Draw(img)
    d.text((margin, margin), title, font=fs_title, fill=(20, 20, 20))
    y = margin + 52
    for i, (t, desc) in enumerate(steps):
        d.rounded_rectangle([margin, y, width - margin, y + boxh],
                            radius=10, outline=(70, 110, 180), width=2,
                            fill=(240, 246, 255))
        d.text((margin + 18, y + 12), t, font=fs_t, fill=(20, 40, 90))
        d.text((margin + 18, y + 44), desc, font=fs_c, fill=(70, 70, 70))
        if i < len(steps) - 1:
            cx = width // 2
            d.line([cx, y + boxh, cx, y + boxh + gap - 8], fill=(120, 120, 120), width=2)
            d.polygon([(cx - 7, y + boxh + gap - 12), (cx + 7, y + boxh + gap - 12),
                       (cx, y + boxh + gap - 2)], fill=(120, 120, 120))
        y += boxh + gap
    p = out if os.path.isabs(out) else os.path.join(IMG, out)
    img.save(p)
    return p


def term(lines, out, title='terminal', width=980, font_size=15):
    """lines: 终端输出行（ASCII，等宽渲染）"""
    f = _f(MONO, font_size)
    lh = font_size + 6
    h = 46 + lh * (len(lines) + 2)
    img = Image.new('RGB', (width, h), (30, 32, 36))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, 30], fill=(52, 55, 60))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 22, 9, 26 + i * 22, 21], fill=c)
    d.text((100, 8), title, font=_f(CN, 14), fill=(200, 200, 200))
    y = 40
    for ln in lines:
        d.text((16, y), ln, font=f, fill=(220, 220, 220))
        y += lh
    p = out if os.path.isabs(out) else os.path.join(IMG, out)
    img.save(p)
    return p
