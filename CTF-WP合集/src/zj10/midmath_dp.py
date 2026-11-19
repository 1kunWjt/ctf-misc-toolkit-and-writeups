# -*- coding: utf-8 -*-
"""第 10 题 MidMath —— 读 out 做三角 DP，复现 exe 里的随机游走与阈值比较。

用法：python midmath_dp.py [out 文件路径]
"""
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else 'out'

rows = []
for line in open(OUT):
    if line.strip():
        rows.append([int(x) for x in line.split()])
n = len(rows)
flat = [v for r in rows for v in r]
print('[*] 行数 = %d，首行 %d 个数，末行 %d 个数' % (n, len(rows[0]), len(rows[-1])))
print('[*] 数字总数 = %d，min = %d，max = %d，均值 = %.3f'
      % (len(flat), min(flat), max(flat), sum(flat) / len(flat)))

# DP：best[i][j] = max(best[i-1][j-1], best[i-1][j]) + a[i][j]
best = [[0] * len(rows[i]) for i in range(n)]
for i in range(n):
    for j in range(len(rows[i])):
        if i == 0:
            best[i][j] = rows[i][j]
            continue
        up_left = best[i - 1][j - 1] if j > 0 else 0
        up = best[i - 1][j] if j < len(rows[i - 1]) else 0
        best[i][j] = max(up_left, up) + rows[i][j]
mx = max(best[n - 1])
print('[OK] 最大路径和 = %d = 0x%X' % (mx, mx))
print('[i] exe 里的阈值常量 0x65C270 = %d' % 0x65C270)
print('[i] 最大路径和 - 阈值 = %d  → 只有走到最优路径才可能满足 sum > 阈值' % (mx - 0x65C270))

# 复现 MSVCRT rand()（未播种，seed = 1）后的走法
state = 1


def msvc_rand():
    global state
    state = (state * 214013 + 2531011) & 0xFFFFFFFF
    return (state >> 16) & 0x7FFF


col, total, seq = 0, rows[0][0], []
for lv in range(1, n):
    c = msvc_rand() % 2 + 1          # exe: rand()%2+1
    seq.append(c)
    if c == 2:
        col += 1
    if col < len(rows[lv]):
        total += rows[lv][col]
print('[i] 未播种 rand() 前 16 步 =', seq[:16])
print('[i] 该随机游走路径和 = %d，是否 > 阈值：%s' % (total, total > 0x65C270))
