# Bird — Writeup

> 未知赛题包（MISC 附件）· 分类：Misc / 图片与隐写 · 难度：★★★☆☆

| 项目 | 内容 |
|---|---|
| 题目名 | Bird（无扩展名文件 `Bird` + `flag.zip`） |
| 分类 | Misc / 图片与隐写（字节交错、位平面、通道差分、ZipCrypto） |
| 附件 | `Bird` 3,124,044 字节；`flag.zip` 12,228 字节（单条目 `flag`，明文 13,827 字节） |
| 一句话 | `Bird` 是两张 1280×853 PNG（其一反向存储）按字节奇偶交错；卡点是「两图只差 B 通道低幅噪声」与「`flag.zip` 真加密」。 |
| 结果 | 未完成（结构全解出，payload 未取到，见文末「卡点与正解方向」） |

**最终答案**

```
未取得。

已确定（有真实字节支撑）：
  Bird = interleave(PNG_A 补零至 1,562,022 , reverse(PNG_B))，步长 2
  PNG_A、PNG_B 均 1280×853 / depth 8 / color type 2；
  R、G 逐像素完全相同，仅 B 差 ±5 量级的块相关噪声
  flag.zip 是真 ZipCrypto（不是伪加密），口令未爆破成功
flag 串未出现在任何产物里，本合集不编造。
```

## 一、题目长什么样（先建立直觉）

附件两样：`Bird`（3,124,044 字节，没有扩展名，双击没反应）和 `flag.zip`（12,228 字节，要密码）。

`Bird` 的头 16 字节（真实 hexdump）是 `89 82 50 60 4E 42 47 AE 0D 44 0A 4E 1A 45 0A 49`，不像任何正常格式。但只看**偶数下标**：`下标 0,2,4,6,8,10,12,14 -> 89 50 4E 47 0D 0A 1A 0A`，正好是 PNG 八字节魔数；奇数下标 `82 60 42 AE 44 4E 45 49` 则是另一路数据的开头。长度 3,124,044 是偶数，两半各 1,562,022 字节 —— 于是第一个结论直接成立：**`Bird` 把两路字节流按「1 字节 A、1 字节 B」交错拼起来**。这类题的固定套路是「拆开 → 有一半（或反向的一半）是合法文件 → 剩下的部分或两张图的差就是载荷」。

## 二、思路总览

> 结论先行：**结构层已彻底解开（两张 PNG，且能证明是同一张照片的两次编码），但 `Bird` 里没有任何“额外”载荷；密码只能从 `flag.zip` 侧解决 —— 而它是真 ZipCrypto。**

五步链路：

1. 试步长与方向：步长 2、偶数位正向 → PNG；奇数位**反向** → PNG。正反都要试。
2. 查两路尾部：偶数路 IEND 之后还有 430,041 字节，全是 `0x00`，是补齐填充，不是数据。
3. 两张图解出来，逐通道比对：R、G 完全一致，**只有 B 不同**。
4. 针对“只有 B 差”打三种：位平面抽取、分块统计（找块级调制）、通道差分/放大/模糊残差；三条都拿不到可读数据就回容器层（IDAT、元数据、填充）确认无隐藏字节。
5. 确认图侧无载荷 → 转去打 `flag.zip` 口令。

```
Bird ─[b[0::2]]→ PNG_A(1,131,981)+430,041 零填充   ┐
     └[b[1::2]]→ reverse → PNG_B(1,562,022)        ├→ R/G 全同，仅 B 差 ±5 块噪声
                                                   ┘
   位平面 / 分块统计(4~64) / 通道差分 ──均无可读数据──→ flag.zip：真 ZipCrypto，口令缺
```

## 三、逐步复现

### 3.1 拆流：步长 2 + 正反双向

现场脚本 `deinterleave.py` 是这一步的最小实现：

```python
b = open(os.path.join(wp, "Bird"), "rb").read()
even, odd = b[0::2], b[1::2]
open(os.path.join(wp, "bird_even.bin"), "wb").write(even)
open(os.path.join(wp, "bird_odd.bin"),  "wb").write(odd)
print("even head:", binascii.hexlify(even[:32]).decode())
```

真实输出（`report.txt`）：

```
Bird len 3124044 even 1562022 odd 1562022
even head: 89504e470d0a1a0a0000000d494844520000050000000355   sig ok: True
odd  head: 826042ae444e4549000000008a1ddab27253621702fffa13…
odd  tail: 5503000000050000524448490d0000000a1a0a0d474e5089
even tail: 00000000000000000000000000000000
```

**怎么读**：`even head` 后面紧跟 `0000000d 49484452`（IHDR 长度 13 + `IHDR`），再后面 `00000500 00000355` = 宽 0x0500 = **1280**、高 0x0355 = **853**，所以偶数路是完整 PNG。`odd tail` **倒着读**才是 PNG 头（`…474e5089` 反序即 `89 50 4E 47…`），说明奇数路要整体反转。`even tail` 全零 —— 偶数路的 PNG 到 1,131,981 字节就结束了。

### 3.2 还原两张图，确认填充

`even` 路的 IEND 在 1,131,969，PNG 结束于 1,131,981（22 个 chunk，sha256 前缀 `c4863ecb3826869080d1bd53`）；IEND 之后还有 430,041 字节，**unique bytes = 1（全 0x00）**。`odd` 路整段反转才是合法 PNG（PNG_B），长度 1,562,022 —— `1,131,981 + 430,041 = 1,562,022` 严丝合缝，**作者为了让两路等长才补的零**，填充本身只有一种字节值，没有信息。落地为 `bird_decoded.png`（PNG_A）与 `bird_rev.png`（PNG_B）。

### 3.3 编码器指纹：这是两次不同编码

不用看图，只看 chunk 头就能定性（我自己走了一遍两图）：

| | `bird_decoded.png`（PNG_A） | `bird_rev.png`（PNG_B） |
|---|---|---|
| 尺寸 / 深度 / 类型 | 1280×853 / 8 / 2（RGB） | 1280×853 / 8 / 2（RGB） |
| 辅助 chunk | **有 `sRGB`、`gAMA`** | **没有** |
| IDAT 分块 | 首个 65,466，其后 65,524（≈64 KB） | 全部 **8,192** |
| 文件长度 | 1,131,981 | 1,562,022 |

两个结论：① 同一张照片被两个不同编码器各写了一次，8,192 字节 IDAT 是 pypng 的典型指纹，所以第二张图很可能是**脚本生成**；② PNG_B 比 PNG_A 大 38%，但下面会看到像素上几乎一样。

### 3.4 逐通道比对：只有 B 被动过

| 指标 | 数值 |
|---|---|
| R / G 通道 | 逐像素**完全相同**（mean 0.00、max 0） |
| B 差值 | 均值 3.66、**最大 158**；有差异像素约 71% |
| 完全无差异的整行 | **175 / 853**（列方向没有） |
| 线性拟合 | `B2 ≈ 0.9896·B1 + 1.86`，残差 std 5.47 |
| 高频差值 | `0, -1, 2, -2, 4, 3, 1, -3, -4, -5 …` |

**为什么这组数字重要**：若两张图是“同一照片存两次 PNG”，R、G 不可能逐像素一模一样；R/G 全同 → **只有 B 通道被人改写过**。差值集中在 ±5 且拟合斜率≈1，说明改动低幅、块相关，像一次量化残差；但 `max = 158` 说明有少量跳远的像素，因此**不是**干净的“低 2 bit 替换”（那样差值不会超过 3）。

### 3.5 位平面抽取（最正统的 LSB 路线）

`bitstream.py` 干三件事：低位一致率、按 1/2/3 bit 抽流找魔数、符号位/差异位抽流。

```python
for n in (1, 2, 3, 4):                      # 低位一致率
    m = (1 << n) - 1
    print("low %d bits: agree %.4f" % (n, ((B1 & m) == (B2 & m)).mean()))

bits = np.stack([(B >> k) & 1 for k in range(n-1, -1, -1)], axis=-1).reshape(-1)
scan(pack(bits),       "%s low%d rowmajor MSBfirst" % (name, n))   # 行优先
scan(pack(bits[::-1]), "%s low%d rowmajor reversed" % (name, n))   # 整段反转
scan(pack(np.stack(...).transpose(1, 0, 2).reshape(-1)), "%s colmajor" % name)  # 列优先
```

产物与判据：`B1.png`（393,130 B）、`B2.png`（538,718 B）是 B 通道灰度图，肉眼无差；`B1_lsb.png`（218,111 B）、`B2_lsb.png`（233,087 B）是 bit0 平面，**两者都呈现清晰的鸟轮廓**而不是雪花噪点。

这一点就是判据：**LSB 被数据替换过的话，平面会长成“雪花”**；现在它与图像内容强相关，说明低位还是照片自身的，**没有塞载荷**。`Blsb_xor.png`、`Blsb1_xor.png`（两图 bit0/bit1 的 XOR）也没有字。

### 3.6 分块统计：验证“每块 1 bit”的块级调制

```python
for bs in (4, 8, 16, 32, 64):
    hb, wb = H // bs, W // bs
    m = d[:hb*bs, :wb*bs].reshape(hb, bs, wb, bs).mean(axis=(1, 3))
    hist, edges = np.histogram(m, bins=14)
    bits = (m > 0).astype(np.uint8).ravel()      # 每块 1 bit
    scan(np.packbits(bits).tobytes())
```

真实结论：`4×4 / 8×8 / 16×16 / 32×32 / 64×64` 的块均值、块内 std、块内 `|d|` 均值**全部单峰**，没有出现“两簇”；把块均值 `> 0` 当 1 bit 抽流，解出的字节没有可打印串。`blockbits.py` 还把 8×8 邻域原值打出来看：块内差值既有 0 也有 ±5，**不是常数偏移**，再一次否掉“整块加同一量”的写法。

“175 行零差异”也当 1 bit/行试过（`853 bit ≈ 106 字节`）：零差异行列表 `[1, 3, 4, 5, 23, 29, 49, 50, 65, 72, 74, 75, 89, 90, 92, 98, 100, 102, 112, 115, …]`，间隔 `2,1,1,18,6,20,1,…` 没有 8 位一组的节奏；按 50 行分箱统计在 y 轴上**分布均匀**，不像人为条纹。结论：**不是行编码**。

### 3.7 通道差分 / 放大 / 模糊残差

`bluediff.py` 出四种可视化（有符号放大、直接 XOR、bit0 XOR、bit1 XOR），另有一组“先模糊再相减”的残差图：

| 产物 | 做法 | 结果 |
|---|---|---|
| `Bdiff_signed_x4.png` / `Bxor.png` | 差值×4 居中 / B1 XOR B2 | 均匀灰噪，无字 |
| `diff_blur04/08/16/32.png`、`resid_x4.png`、`resid_abs_x8.png` | 模糊后相减、残差放大 | 只有照片边缘与纹理 |
| `diff_heat.png` / `sign_map.png` / `eq_map.png` / `crop_diff.png` | 热力图 / 符号图 / 等值图 / 局部裁剪 | 差异均匀铺满，局部也无字 |

再补一个判据：切成 32×32 网格统计“差值 > 20 的像素数”，每块都在 25–30 之间 —— **高差像素均匀分布**，没有“某块特别密”的局部对象。藏字/藏图一定成片，这里没有。

### 3.8 容器层排查（IDAT、尾部、元数据、填充）

`idatcheck.py` 检查 IDAT 拼起来的 zlib 流有没有“解压完还剩字节”（最常见的“PNG 里塞文件”手法）：

```python
z = zlib.decompressobj(); out = z.decompress(blob)
print("inflated %d B, eof=%s, unused_data=%d B" % (len(out), z.eof, len(z.unused_data)))
```

结果：**两张图都 `unused_data = 0`**，inflate 干净收尾；无 `tEXt/iTXt/zTXt`、无 `eXIf`、无多余 chunk；`Bird` 填充段唯一字节值 `0x00`。到这一步可以下硬结论：**`Bird` 里除了两张 PNG 的像素，没有别的东西。**

### 3.9 转向 `flag.zip`

自己复算 `flag.zip` 本地头（不依赖解压软件）：

```
size = 12,228   sig = 0x04034B50   version = 20
flags = 0x0009  method = 8 (deflate)
crc = 0xa6c82cb4   csize = 12,086   usize = 13,827   name = "flag"
```

要点：`flags = 0x0009` = bit0（加密）+ bit3（data descriptor），bit0 置位即传统加密；`method = 8`，压缩率 0.87（13,827 字节明文若是图则是小图，若是文本则是短文，**未验证**）。**伪加密排除**：把 bit0 清掉另存 `flag_fixed.zip`（`flags = 0x0008`）后直接解 deflate 会报错 —— 所以是**真 ZipCrypto**。

`zipcrack.py` 是纯标准库多进程实现，只解 12 字节加密头、用校验字节先筛：

```python
def keys_init(pwd):
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for c in pwd:
        k0 = crc32_byte(k0, c)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = crc32_byte(k2, (k1 >> 24) & 0xFF)
    return k0, k1, k2          # 再解 12 字节头，用校验字节先筛
```

实测速度（真实测量）：**单进程 200,000 词 / 1.7 s ≈ 12 万/秒/核**，8 进程跑 14M 行 rockyou 约 20 s。已试过的规模：**全部纯数字 0–99,999 + 一批常见词/鸟类词/文件名，未命中**；rockyou 全量当时未跑（见文末）。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| 字节步长交错 | 两路数据 1 字节 A、1 字节 B 交替存放 | `Bird` 偶数位就是 PNG 魔数，一眼定性 | 双图题、音频双声道、双流合一 |
| 反向存储 | 某一路整体倒着放 | 奇数路必须 reverse 才是 PNG | 出题人常加的“别扭感” |
| 编码器指纹 | 同图不同库的 chunk 结构不同（IDAT 分块、有无 sRGB/gAMA） | 证明“两次编码”而非复制 | 判图是否二次处理、溯源工具链 |
| 单通道改写 | 只动 B，R/G 逐像素不变 | R/G 全同 → 锁定 B 是唯一被写通道 | 通道隐写、盲水印 |
| 位平面判据 | LSB 平面有结构＝无载荷，雪花＝被替换 | bit0 平面呈鸟轮廓，直接否掉 LSB 载荷 | Stegsolve / zsteg / 分块藏 1 bit |
| ZipCrypto 加密头 | 每条目 12 字节头，末字节可校验 | 先解 12 字节即可筛，爆破提速上百倍 | 一切 zip 口令爆破 |
| 伪加密 vs 真加密 | 伪加密清标志位即可解；真加密清了 inflate 报错 | 本题属后者，只能爆破/已知明文 | ZIP 类 Misc 的第一道判断 |

## 五、踩坑与陷阱

1. **只试正向不试反向**：偶数路正向就是 PNG，容易以为“找到就完事”，漏掉奇数路要反转。
2. **把 430,041 字节填充当载荷**：`unique bytes = 1`（全零），第一步就该排除，别在上面做熵分析。
3. **误判“R/G 全同”**：直觉说两次编码 R/G 也会变；正因全同，才能反证“只有 B 被写过”——这是本题最强证据。
4. **把 `max |d| = 158` 当强信号**：它只出现在极少数像素且分布均匀；真藏字会成片。
5. **拿本地的 `Bird.png`（3,124,037 字节）当原图**：那是实验副产物，头部都不是干净 PNG，会带偏。
6. **伪加密别靠肉眼**：必须“清 bit0 → 试解 → 看 deflate 是否报错”；同理，在 IDAT 里找多余字节前先怀疑填充，`unused_data` 才是权威判据（本题为 0）。

## 六、赛场 20 分钟行动清单

1. `0–2 min`：`xxd Bird | head`，看偶数位是否 PNG 魔数；顺手判长度奇偶。
2. `2–5 min`：步长 2 拆两路，**正反都试**，用头部/`file` 确认哪路是 PNG。
3. `5–7 min`：查两路尾部；有填充先量 `unique bytes`，为 1 立刻放弃。
4. `7–11 min`：两张图解出，逐通道做差：先看 R/G 是否全同，再看 B 的 mean/max、差异像素比、整行零差异数。
5. `11–15 min`：按“只有 B 差”打三件套：bit0/bit1 平面、块统计直方图、XOR/放大差分。**单峰 + LSB 有轮廓 → 判定无载荷**。
6. `15–20 min`：容器层排查（IDAT `unused_data`、`tEXt`、填充）后立刻转 `flag.zip`：先判伪加密，再上字典爆破，两条线并行。

> 20 分钟没拿到可读数据就切 zip 爆破，并把“图侧无载荷”的结论写进 WP —— 这题的分很可能就在“证明没有载荷”上。

## 七、附件与脚本

| 路径 | 说明 |
|---|---|
| `misc_attachment/Bird`、`flag.zip`、`flag_fixed.zip` | 原始附件与“清掉加密位的副本”（`flags` 0x0009 → 0x0008） |
| `misc_attachment/bird_even.bin` / `bird_odd.bin` | 步长 2 拆出的两路，各 1,562,022 字节 |
| `misc_attachment/bird_decoded.png` / `bird_rev.png` | 两半还原出的 PNG（1,131,981 / 1,562,022 字节） |
| `misc_attachment/B1.png`、`B2.png`、`B1_lsb.png`、`B2_lsb.png` | B 通道灰度图与 bit0 平面（关键判据） |
| `misc_attachment/diff_blur0*/resid_x4/Bdiff_signed_x4.png` 等 | 差分、放大、模糊残差可视化 |
| `misc_attachment/deinterleave.py` / `report.txt` | 拆流脚本与真实输出（长度、魔数、chunk 表、IHDR、填充统计） |
| `misc_attachment/bitstream.py`、`blockhist.py`、`blockstd.py`、`blockbits.py` | 位平面扫描；4~64 块统计与双峰检验；8×8 邻域原值 |
| `misc_attachment/bluediff.py`、`blurdiff.py`、`idatcheck.py`、`cmpbird.py` | 通道差分/模糊残差；IDAT 尾部检查；对比本地 `Bird.png` |
| `misc_attachment/zipcrack.py` / `slice200k.txt`、`slice2m.txt` | ZipCrypto 多进程爆破；rockyou 切片实测速度 |

跑法：`python deinterleave.py` → `bitstream.py` → `blockhist.py` → `idatcheck.py`；爆破用 `python zipcrack.py flag.zip <字典> 8`。

## 卡点与正解方向

**已确认（有真实字节/产物支撑）**

1. `Bird` = `interleave(PNG_A 补零, reverse(PNG_B))`，步长 2，两路各 1,562,022 字节。
2. 两图均 1280×853 / depth 8 / color type 2；PNG_A 有 `sRGB`+`gAMA`+64 KB IDAT，PNG_B 只有 8,192 字节 IDAT（pypng 指纹）→ **两次不同编码**。
3. `Bird` 内部**无额外载荷**：IDAT `unused_data = 0`、无文本/EXIF chunk、填充段全 `0x00`。
4. 像素层只有 B 被改：R/G 逐像素全同；B 差均值 3.66、最大 158、71% 像素不同、175 行零差异、`B2 ≈ 0.9896·B1 + 1.86`（残差 std 5.47）；位平面、块统计（4–64 全尺度单峰）、通道差分/放大/模糊残差、零差异行编码，**四种写法全部排除**。
5. `flag.zip` 是真 `ZipCrypto`（`flags=0x0009`、`method=8`、`crc=0xa6c82cb4`、`csize=12,086`、`usize=13,827`），清加密位后 inflate 报错。

**卡在哪**：`flag.zip` 的口令。图侧已能证明“无载荷”，口令只可能来自**题目描述/其他附件**（本附件包内没有）或**弱口令**。

**正解方向（按性价比）**

1. **跑 rockyou 全量**（最直接），按实测 12 万/秒/核，8 进程 14M 行约 20 s：

```powershell
python zipcrack.py flag.zip "C:\...\01-rockyou-136M.txt" 8
```

   当时字典在 `C:\Users\XiaoMibook\Desktop\CTF\misc\常用弱口令字典\01-rockyou-136M.txt`（14M 行）；写这篇时该路径已不存在（`Test-Path` 为 `False`），换任意 rockyou 即可。未命中就叠规则：首字母大写、后缀 `123`/`!`/年份。

2. **已知明文（bkcrack）**：需要 ≥12 字节**连续**的已知明文且必须是压缩后的字节；本题 `method=8`（deflate），明文无法直接映射压缩流，所以只有“明文是 PNG 且作者改用 store”时才可行 —— 本附件不满足。
3. **回题目源**：`Bird` 与 `flag.zip` 一起发，口令大概率写在题目描述里（这类双附件题几乎不会让你纯爆破）；本地征集目录没有描述文件，属信息缺失。拿到口令后，`flag` 条目明文 13,827 字节，先 `file`；若还是图，按 3.3–3.8 再走一遍 —— 很可能真 flag 在 zip 里那张图上，`Bird` 只是“教方法”的引子。
