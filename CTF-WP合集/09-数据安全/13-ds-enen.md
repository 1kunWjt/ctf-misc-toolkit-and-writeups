# ds-enen — Writeup

> 省赛「数据安全」赛道（题型复现） · 分类：数据安全（磁盘取证 + 文件恢复 + 压缩包口令） · 难度：★★★☆☆

| 项目 | 内容 |
|---|---|
| 题目名 | ds-enen（第 13 题） |
| 分类 | 数据安全（VHD 固定盘 → MBR → FAT16 → 删除恢复 → ZipCrypto 口令） |
| 附件 | `DS附件\enen.zip` 497,086 字节 → `data.vhd` 39,846,400 字节 |
| 一句话 | 从固定 VHD 里按 FAT16 目录项把被删除的 `DATA.ZIP` 连续块捞出来，再用 EOCD 自校验；口令这一层没打通 |
| 结果 | 未完全拿下（见文末《卡点与正解方向》）：`DATA.ZIP` 已按字节精确恢复并验证，包内 `data.csv` 仍在 ZipCrypto 之后 |

**最终答案**

```
未完成 —— 未取得 flag
（已确证：目标文件是 DATA.ZIP 内的 data.csv，加密方式为 ZipCrypto 真实加密）
```

## 一、题目长什么样（先建立直觉）

附件解开只有一个 `data.vhd`，39,846,400 字节。`.vhd` 不是文件系统，是**虚拟磁盘**：要么是“裸磁盘镜像 + 末尾 512 字节 footer”，要么是带动态头的稀疏格式。判断依据就在最后 512 字节的 `conectix` 结构里，`disk type` 字段一眼定性。

定性成 Fixed 之后，这个文件就等价于一块 38 MB 的硬盘：前 512 字节是 MBR，分区表第 1 项指向 LBA 2048，那里是 FAT16 的引导扇区。整条链路是标准的「裸盘 → 分区 → 文件系统 → 删除项恢复」，属于数据安全赛道最典型的**数据恢复工程**：不是靠猜，而是靠每一层结构自带的自校验字段（footer checksum、`55AA`、BPB 参数、EOCD 偏移）互相钉死。真正卡住人的不是磁盘，是最后一步：恢复出来的 ZIP 里那个 `data.csv` 被 ZipCrypto 加密了，`general purpose flag` 的 bit0 与 bit3 同时置位，两个头里都写着“加密”，`zlib` 直接 inflate 会报 `invalid distance too far back`。

## 二、思路总览

1. 读末尾 512 字节 VHD footer → 定 `disk type = 2 (Fixed)`，`checksum` 自校验通过；
2. 读 MBR（偏移 446 起 4×16 字节）→ 第 1 分区 `type=0x06 (FAT16)`，`startLBA=2048`，`75776` 扇区；
3. 读 VBR 的 BPB → 512 B/扇区、2 扇区/簇、保留 8 扇区、2 个 FAT、每个 FAT 148 扇区、根目录 512 项；
4. 算布局：`FAT1=0x1000`、`ROOT=0x26000`、`DATA=0x2A000`，簇 N 的偏移 = `0x2A000 + (N-2)*1024`；
5. 走根目录 → 命中一个首字节被写成 `0xE5` 的删除项 `\xE5ATA.ZIP`，首簇 5、声明长度 454,814；
6. FAT 链已被清零 → 只能按**连续块** carve 445 个簇；
7. 用 ZIP 自己的 EOCD 反算真实长度做交叉校验（这一步把“猜”变成了“证明”），再解析 LFH／CDH → 确认 `data.csv` 是 deflate + ZipCrypto → 口令层。

## 三、逐步复现

### 3.1 第一步：VHD footer 定性（`01_vhd_footer.py`）

固定盘 VHD 的 footer 永远在文件末尾 512 字节，且 `checksum` 是“把 checksum 字段清零后所有字节求和取反”，能自己验证自己：

```text
[*] file size  = 39846400 bytes (38.00 MB)
[*] footer offset = 0x2600000 (file_size - 512)
cookie       = b'conectix'
features     = 0x00000002
file fmt ver = 0x00010000  (1.0)
data offset  = 0xFFFFFFFFFFFFFFFF  (=> Fixed, no dynamic header)
creator app  = b'win '   creator os = b'Wi2k'
original size= 39845888 bytes (38.00 MB)
current size = 39845888 bytes (38.00 MB)
geometry     = 03930511      -> 915 cyl / 5 heads / 17 spt
disk type    = 2  (Fixed)
checksum     = 0xFFFFE768   calc=0xFFFFE768 -> OK
unique id    = b109d418117b71418bc07e8fd6387075
```

怎么读这个输出：`data offset = 0xFFFFFFFFFFFFFFFF` 是固定盘的标志（动态盘这里会指向动态头），`current size = 39,845,888` 加上 512 字节 footer 正好等于文件大小 —— 说明尾部没有被截断，磁盘内容从偏移 0 开始。`checksum OK` 说明这 512 字节没被人改过，后面的偏移可以直接信。

### 3.2 第二步：MBR 分区表（`02_mbr.py`）

```text
[*] signature 55AA at 510      = 55aa
[*] disk signature (offset 440) = 6da55bf6
entry1: status=0x80 type=0x06(FAT16 ) startLBA=2048     sectors=75776    size=38797312 bytes (37.00 MB)
entry2/3/4: type=0x00 sectors=0
```

`status=0x80` 是活动分区标记，`type=0x06` 是 FAT16（LBA 寻址）。分区从 LBA 2048（=1 MiB 对齐）开始，75776 扇区，正好落在文件长度之内。

### 3.3 第三步：BPB 与布局推演（`04_fat16.py`）

VBR 里读出来的 BPB：

```text
OEM          = b'MSDOS5.0'
bytes/sector = 512, sectors/cluster = 2, reserved = 8, numFATs = 2
root entries = 512, total sec16 = 0, media = 0xF8, FAT16 size = 148
fs type      = b'FAT16   '
```

`total sec16 = 0` 是 FAT16 大分区的常规写法（总扇区数放进偏移 0x20 的 32 位字段，这里等于分区表给的 75776）。据此算四个关键偏移：

```text
cluster size    = 1024 bytes
FAT1 offset     = 0x1000   (扇区 8)
ROOT DIR offset = 0x26000  (扇区 304，512 项 = 32 扇区)
DATA offset     = 0x2A000  (扇区 336)
data clusters   = 37720
```

**这里的簇偏移公式是最容易错的一步**：FAT 簇号从 2 开始，第 1、2 项是保留项，所以 `offset(N) = DATA + (N-2)*1024`。写错成 `(N-1)` 会让所有目录项都“看起来是乱码”，并且会误判“文件系统被破坏”。本题用两个系统目录反证公式：`System Volume Information` 的首簇 2 落在 `0x2A000`（读出正好是 `.` 与 `..` 两个目录项），`$RECYCLE.BIN` 的首簇 450 落在 `0x9A000`（同样以 `.`/`..` 开头），公式成立。

### 3.4 第四步：根目录里的删除项（本题的题眼）

根目录只有三个项：

```text
slot2   b'SYSTEM~1   ' attr=0x16(DIR|HID|SYS) clu=2    size=0
slot3   b'\xe5ATA    ZIP' attr=0x20(ARC)    clu=5    size=454814   DELETED
slot4   b'$RECYCLEBIN' attr=0x16(DIR|HID|SYS) clu=450  size=0
```

删除项的特征是首字节被写成 `0xE5` —— FAT 删除文件时会把文件名的第一个字符替换成 `0xE5`，所以原名只剩 `ATA.ZIP`，`?` 位最常见的还原就是 `D`（`DATA.ZIP`，后面 ZIP 内部的文件名 `data.csv` 也印证了这一点）。目录项本身**没有被清掉**，首簇号和文件长度都还在，这就是恢复的全部依据。

回收站是空的（只有 `desktop.ini` 的 `[.ShellClassInfo]`），没有 `$I`/`$R` 配对文件 —— 说明文件不是“删进回收站”，而是被直接删除（Shift+Del 或命令行 `del`），这解释了为什么 FAT 链是干净的零。

### 3.5 第五步：连续块 carve + EOCD 交叉校验（`06_recover.py`）

```text
=== cluster formula verification ===
  cluster 2   -> 0x02A000  head=b'.          \x10\x00k\x0c...'   (SVI dir data)
  cluster 5   -> 0x02AC00  head=b'PK\x03\x04...'                (?ATA.ZIP first cluster)
  cluster 450 -> 0x09A000  head=b'.          \x10\x00\x8b\x10...' ($RECYCLE.BIN dir data)
  FAT[5] chain walk = [5]  <-- 删除时链被清 0
```

`FAT[5]` 已经不是一个有效指针，链断了，只能按“文件在磁盘上是连续存放的”这个假设整段抠出来：`445 簇 × 1024 = 455,680` 字节，取前 454,814 字节。连续块之所以成立，是因为簇 5 的第 445 个簇（簇 449）结束在 `0x9A000`，正好是下一个已分配块 `$RECYCLE.BIN` 的起点 —— 中间没有别的文件插进来。

抠出来之后**必须让 ZIP 自己签字**：

```text
=== EOCD cross-check ===
  EOCD at 0x6F088 (absolute 0x99C88)
  entries=1/1 cdsize=90 cdoff=454702
  => ZIP begins at carved offset 0x0, total 454814 bytes (dir entry says 454814) MATCH=True
```

两个独立来源给出同一个数字：FAT 目录项声明 454,814，EOCD 内部偏移反算也是 454,814，且 LFH 的 `PK\x03\x04` 就在 carve 区第一个字节。这条校验是整题最硬的证据 —— 它把“我猜文件是连续的”变成“这段字节确定是一个完整 ZIP”。

顺带确认了恢复结果的完整性（本地复算，与 `solve\extract\DATA.ZIP` 逐字节相同）：

```text
DATA.ZIP bytes 454814
sha256(zip)   7be8861c1bb97f2246219d8e285acc9fbbc8cbd571d598256ab86dfc6bd66df5
md5(zip)      2dae13d484995ab24548823fd8c75064
sha256(carve) 7be8861c1bb97f2246219d8e285acc9fbbc8cbd571d598256ab86dfc6bd66df5  一致: True
```

### 3.6 第六步：ZIP 内部结构 —— 这里开始不对劲

```text
=== ZIP local file header ===
  version=0x0014 flags=0x0009 (bit0=encrypted, bit3=data descriptor)
  method=8 (deflate)
  crc32=0x75334E90  comp_size=454648  uncomp_size=628623
  filename=b'data.csv' extra_len=0  data_start=0x26
=== CDH @0x6F02E ===
  flags=0x0009 method=8 crc=0x75334E90 csize=454648 usize=628623 name=b'data.csv' lho=0x0
```

三个可疑点，逐个排查：

1. **`flags=0x0009`**：bit0（加密）+ bit3（数据描述符）。LFH 与 CDH 两处标志一致，所以不是“伪加密”（伪加密只会改一处）。
2. **bit3 置位却把 CRC/长度填满**：正常写入器置 bit3 时会把这三个字段写成 0，这里全是真值 —— 头是被人为拼过的。
3. **payload 直接 inflate 失败**：0～64 每一个偏移、`wbits=-15/15/47` 都试过，全部失败；只报 `invalid distance too far back`。

再补两刀，确认它不是“换个 deflate 起点”就能救的：

```text
== 尝试不同起点/窗口直接 inflate ==
  0..64 全部失败 -> 密文/非 deflate
== 单字节 XOR 探针 ==  单字节异或命中: none
== 熵与直方图 ==   Shannon entropy = 7.9991 bits/byte ; 字节种类 = 256/256
  contains b'PK\x03\x04' : False    contains b'data.csv' : False
  contains b'姓名'(GBK)  : False    contains b'姓名'(UTF-8): False
```

熵 7.9991 且 256 种字节全出现，加上明文里连 CSV 表头都找不到 —— 数据是真的被加密了，不是编码错位。ZipCrypto 的判据也很干净：

```text
flags bit3=8 -> 校验字节取 修改时间高字节 = 0xAD
12 字节加密头 = f28daab397ac68e2228c7882
```

### 3.7 第七步：口令尝试（到这一步为止）

先写了一个“只校验 12 字节加密头”的快速判定器（`zipcrack.py`）：ZipCrypto 是流密码，解密 12 字节头，第 12 字节应等于“CRC 高字节”或“修改时间高字节”。这条判据只有 1/256 的强度，**当场就出了假阳性**：

```text
[FOUND] 口令 = 'ctf123456'  （试了 N 个）
        首段明文 = b''      <-- 解压时 zlib 报错
```

于是换成 `zipcrack2.py`：头校验通过后，再解 256 字节并试 inflate，能持续解出 ≥64 字节才算数。字典、组合、纯数字三种模式全跑：

```text
[i] 校验字节=0xad  crc=75334e90
[FAIL] dict 无命中（35 个）
```

（上面这一段是本地复跑 `zipcrack2.py dict` 得到的真实输出；会话记录里 `full` 与纯数字 1～8 位模式同样没有命中。纯 Python 的密钥推进速率大约 10⁵ 量级/秒，8 位纯数字要跑到天亮。）

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| VHD footer | 末尾 512 字节的 `conectix` 结构，含磁盘类型/几何/大小，checksum 可自校验 | 一眼区分 Fixed/Dynamic，并把 39 MB 裸盘当成硬盘读 | Hyper-V/取证镜像、`qemu-img info` 同类元数据 |
| MBR + EBR 链 | 偏移 446 起 4×16 字节分区项，`status/type/LBA/扇区数` | 定位分区起点 2048，避免把 VBR 当成 MBR | 所有磁盘取证、分区恢复 |
| BPB | VBR 里的 FAT 参数（bps/spc/rsvd/nfat/rootent/fatsz） | 手算 FAT/根目录/数据区三个偏移 | FAT12/16/32、exFAT 解析 |
| FAT 簇号从 2 起 | 簇 0/1 是保留项，`offset = DATA + (N-2)*簇大小` | 写错这一格就会全盘“乱码”，本题用两个系统目录反证 | 所有 FAT 恢复工具（testdisk 等） |
| 删除标记 `0xE5` | FAT/dirent 删除时首字节被替换，首簇与长度保留 | 首字符丢失但文件仍可定位、可按长度 carve | NTFS 的 `$Bitmap`、ext4 的 data-run 回收 |
| 连续块 carve + EOCD 反算 | 链断了按“物理连续”整段抠，再用 `zip_start = eocd - cdsize - cdoff` 验证边界 | 直接删除后链被清零，唯一可行恢复；EOCD 让“看起来像”变成“确实是” | 裸 carv（photorec）、拼接修复 |
| ZipCrypto 校验字节 | 12 字节加密头末字节 = CRC 高字节或 modtime 高字节 | 快速判口令对错，但只有 1/256 强度 | `zip2john`、hashcat 17200/17225 |

## 五、踩坑与陷阱

1. **簇偏移写错一格，整盘读不出来。** 第一版用了 `DATA + (N-1)*1024`，结果三个目录项全是垃圾，还差点得出“文件系统损坏、需要重新格式化恢复”的错误结论。修正为 `(N-2)` 后 `$RECYCLE.BIN` 和 SVI 的 `.`/`..` 同时对上了，公式才算验证过 —— 一定要用系统目录或卷标做反证，别靠“看起来像”。
2. **只看加密头就宣布口令命中。** `ctf123456` 的头校验字节正好撞上，如果不是加了“解 256 字节再 inflate”的二次验证，就会拿着错口令去写 WP。
3. **以为恢复出来的就是全部／把 bit3 当证据。** `06_recover.py` 里那段 `[OK] raw-deflate inflate OK` 是脚本的**乐观分支**，实际运行走的是 `[FAIL]` 分支（会话记录里明确是 `invalid distance too far back`）—— 看脚本输出先看它走了哪一支，别被源码里的成功字符串骗了。同理，“bit3 置位却填了 CRC/size”不是伪加密的特征：伪加密是 LFH 与 CDH **不一致**，这里两处一致，只能说明头被手工拼过、加密是真的。

## 六、赛场 20 分钟行动清单

1. `xxd` 看末尾 512 字节，确认 `conectix` 与 `disk type`（2=FAT，3=动态盘要先合并）。
2. MBR 偏移 446 扫 4 项，记下 `startLBA` 与 `type`；`0x06/0x0E = FAT16`。
3. 读 VBR 的 BPB，手算 `FAT/ROOT/DATA` 三个偏移，并打印 `DATA + (2-2)*簇` 看是不是 `.`/`..`。
4. 根目录只看 `首字节 0xE5` 或 `attr & 0x10 == 0` 的项，记下 `首簇 + 长度`。
5. 试 FAT 链；链断就按连续块 carve，长度取目录项声明的值。
6. 得到包就做 EOCD 反算校验，数字对上再往下走。
7. 看 LFH/CDH 的 `flags`：只中一条 = 伪加密（改回 0x00 即可）；两处都中 = 真加密，立刻切 bkcrack/口令路线。

> 20 分钟没摸到“可校验的文件头”，就别再手搓解析器了：直接 `binwalk -e` + `foremost` + `testdisk`，让工具先出结果，再回头补“为什么”。

## 七、附件与脚本

| 脚本 | 作用 |
|---|---|
| `solve\01_vhd_footer.py` | 读末尾 512 字节 footer，打印磁盘类型/几何/checksum 校验 |
| `solve\02_mbr.py` | 解析 4 个分区项，并对首分区做 VBR 指纹识别 |
| `solve\03_recon.py` / `solve\05_locate_zip.py` | 分区级魔数与关键字扫描（`PK`/`PNG`/`DASCTF`/`flag`/可打印串，本题**没有**扫到任何 `DASCTF`/`flag`）；精确界定 ZIP 范围（LFH/CDH/EOCD 全扫）+ 关键偏移 hexdump |
| `solve\04_fat16.py` / `solve\07_tree_and_zip.py` | 手写最小 FAT16 解析器（FAT 链、LFN 拼接、删除项标记）；修正簇公式后重走整棵目录树 + 多偏移 inflate 尝试 |
| `solve\06_recover.py` | 连续块 carve → 写 `extract\DATA.ZIP` → 解析 LFH 并尝试 inflate |
| `solve\zipcrack.py` | ZipCrypto 口令判定（仅 12 字节头，弱校验，会假阳性） |
| `solve\zipcrack2.py` | ZipCrypto 口令爆破（头校验 + 256 字节 inflate 二次验证），`dict/full/num` 三模式 |

产物：`solve\extract\DATA.ZIP`（454,814 字节，sha256 `7be8861c…66df5`）。

## 卡点与正解方向

**已确认（全部有输出支撑）**

- `data.vhd` 是 38 MB 固定 VHD，checksum 自校验通过；MBR 第 1 分区为 FAT16（LBA 2048，75776 扇区）。
- BPB 参数与四段偏移（`0x1000 / 0x26000 / 0x2A000 / 簇 2 起`）互证成立。
- 根目录存在删除项 `\xE5ATA.ZIP`，首簇 5、长度 454,814；FAT 链已被清零。
- 连续块 carve 得到的 454,814 字节由 **EOCD 内部偏移反算**独立验证，长度完全一致；与脚本产物逐字节相同。
- 包内唯一文件 `data.csv`（uncompressed 628,623），`method=8`，`flags=0x0009`，**LFH 与 CDH 一致**，熵 7.9991、无任何明文特征 → 真实 ZipCrypto 加密，非伪加密、非编码错位、非单字节 XOR。
- 12 字节加密头 `f28daab397ac68e2228c7882`，校验字节 `0xAD`（modtime 高字节）。
- 口令层：字典 35 条 + 组合模式 + 纯数字 1～8 位均未命中。

**卡在哪**

- ZipCrypto 的密钥推进不可逆，只能“猜口令”或“用已知明文恢复内部状态”。纯 Python 暴力在 8 位纯数字这一档就撞到速率墙（10⁵ 量级/秒）。
- 想走已知明文攻击，需要 **≥12 字节的 deflate 密文对应明文**；`data.csv` 是 deflate 之后才加密的，能猜到的只有 CSV 表头文本，不是压缩流字节 —— 表头猜测不能直接喂给 bkcrack。

**正解方向（按性价比排序）**

1. **bkcrack（Biham–Kocher 已知明文攻击）**：先用 14 题 `个人信息数据规范文档.pdf` 里给出的列名 `userid,username,password,name,idcard,phone` 构造一个同结构 CSV，用同一压缩器（Windows「发送到 → 压缩文件夹」/ 7-Zip deflate）压出**密文前缀**，拿这段 deflate 字节当已知明文喂 bkcrack；命中后拿内部密钥直接解 454,648 字节，再用 `-k` 出明文。
2. **口令线索回捞**：`data.csv` 是“个人信息”表，题面/平台描述/同批次 14 题共用同一套字段规范，口令极可能就在题目描述或同一套附件的命名里（`enen`、`data`、`DASCTF2024` 这类已试过，未命中，说明不是直白弱口令）。
3. **正规工具链**：`zip2john DATA.ZIP > h.txt` + `hashcat -m 17225 h.txt rockyou.txt -r best64.rule`；若平台允许外带，bkcrack 的 C 实现几秒到几分钟就能出结果，别在 Python 里硬扛。
4. 若最终确认口令不可得，本题的可交付成果就是 **“把 DATA.ZIP 完好恢复出来”** 这一层 —— 从“数据恢复”考点的评分看，carve + EOCD 双证据已经闭环，加密层属于第二段。
