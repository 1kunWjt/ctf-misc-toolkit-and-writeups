# 第 10 题 · MidMath — Writeup

> DASCTF 题包 · 分类：Reverse（与 Crypto 混合） · 难度：★★★★★

| 项目 | 内容 |
|---|---|
| 题目名 | MidMath（第 10 题） |
| 分类 | Reverse（自定义壳 + 数塔 DP） |
| 附件 | `MidMath.zip`（795,960 字节），解出 `MidMath.exe`（1,462,140 字节）与 `out`（667,103 字节） |
| 一句话 | 程序把「随机游走恰好走到最优路径」当作通关条件，而 flag 是壳里的一条常量字符串 |
| 结果 | `DASCTF{path_16-bit_md5_lowercase_encrypt}` |

**最终答案**

```
DASCTF{path_16-bit_md5_lowercase_encrypt}
```

## 一、题目长什么样（先建立直觉）

附件里只有两个文件。`out` 是纯文本，500 行，第 i 行恰好 i 个整数，一共 125 250 个数，取值 1 到 20000，均值 8 582。这种形状只有一种解释——**数字三角形（数塔）**，天然对应"从顶往下走、每步只能走左下或右下"的路径问题。

`MidMath.exe` 是 32 位原生 PE，1.4 MB，MinGW 编译的 C++（导入了 `libgcc_s_dw2-1.dll`、能看到 `__register_frame_info`），不是 .NET、不是 PyInstaller、也不是 Go。

第一眼看上去它有两个非常刺眼的特征：段名是 `DAS0` / `DAS1` / `DAS2`，而不是正常的 `.text` / `.data`；导入表里只有 `LoadLibraryA`、`GetProcAddress`、`VirtualProtect`、`ExitProcess` 四个函数，外加 msvcrt 的 `_iob`。这五个导入是"壳"的标准签名：自己解压、自己改内存属性、自己收尾。

## 二、思路总览

先给结论，再给链路：

1. `out` 是数塔数据，程序要读它；
2. exe 被一层**改造过的 UPX／aPLib 壳**包住（段名被改成 DAS0~DAS2，入口是一段 aPLib 解压桩）；
3. 壳在解压前会**往压缩流里写 4 个字节**（自修改，专门坑静态解包）；
4. 直接运行没有任何输出——不是没跑，是跑完了但条件不满足；
5. 用"把跳 OEP 的指令改成 `jmp $`"的办法让进程停在解压完成那一刻，再用 `ReadProcessMemory` 把镜像抓下来；
6. 在解出来的镜像里找到 `DASCTF{...}`、`out`、`%d`，定位 `main`，还原出"随机游走 + 阈值比较"的判定；
7. 对 `out` 做数塔 DP，发现阈值正好是**最大路径和减一**，即只有走到最优路径才会打印 flag；
8. 把 `out` 换成全 20000 的三角形，真 exe 就会把 flag 打出来，完成动态互证。

## 三、逐步复现

### 3.1 先量化 `out`

```python
rows = [[int(x) for x in l.split()] for l in open('out') if l.strip()]
flat = [v for r in rows for v in r]
print(len(rows), len(rows[0]), len(rows[-1]), len(flat), min(flat), max(flat))
```

输出：

```
500 1 500 125250 1 20000
```

500 行、首行 1 个数、末行 500 个数、12 万多数字全在 1~20000 之间——数塔数据确认。此时先别急着往 IDA 里丢，因为很快会发现它的段表不正常。

### 3.2 段表与导入表：这是壳

`objdump -h` 看到三个段：`DAS0`（虚拟大小 `0x1ea000`，**磁盘大小 0**）、`DAS1`（磁盘 `0x57400`）、`DAS2`（`0x200`）。`DAS0` 是"纯内存段"——典型的解压目标区。入口点 RVA `0x242100` 落在 `DAS1` 末尾。

导入表更干脆，只有：

```
LoadLibraryA  GetProcAddress  VirtualProtect  ExitProcess   (+ msvcrt:_iob)
```

而且整份文件在最后一个段之后还有约 1.1 MB 的**覆盖数据**（overlay），熵值不高，里面能直接看到 `_ZTSt7__cxx1119money_put...` 这类 C++ 修饰名——那是 MinGW 链接器留下的 **COFF 符号表 + 字符串表**（`PointerToSymbolTable = 0x140c00`、`NumberOfSymbols = 21794`，因为文件只有 `0x164FBC` 字节，符号表尾部被截掉了）。

> 顺带说一句：如果没被壳打乱，这份符号表足够把函数名全还原。可惜它被压到文件尾且截断，只能当辅助线索。

### 3.3 入口是 aPLib 解压桩，且会自改压缩流

把入口处的字节按 `i386` 反汇编，得到的是教科书级的 aPLib `aP_depack`：

```
60                pushad
be 15 b0 5e 00    mov  esi, 0x5eb015        ; 源 = DAS1+0x15
8d be eb 5f e1 ff lea  edi, [esi-0x1ea015]  ; 目标 = 0x401000（= DAS0）
8d 87 7c ba 1e 00 lea  eax, [edi+0x1eba7c]  ; = 0x5eca7c
ff 30             push dword [eax]
c7 00 21 47 f5 8a mov  dword [eax], 0x8af54721   ; ← 改压缩流
50                push eax
57                push edi
eb 0c             jmp  short 0x24212a
```

关键在两处：

1. **bit 读取器**是标准的"`add ebx,ebx` 取位 + 归零后 `mov ebx,[esi]` / `sub esi,-4` / `adc ebx,ebx` 续 32 位"，即 aPLib 1.x 的位流；
2. `0x5eca7c - 0x5eb015 = 0x1a67`，也就是说壳在解压前把**压缩流偏移 0x1a67 处的 4 个字节强行改成 `21 47 f5 8a`**，解压完再还原。任何人拿磁盘上的字节直接解 aPLib，都会在这里解错。

解压完成之后还有一段"重定位扫描"：在解出来的代码里找 `E8/E9`（call/jmp rel32）且紧随字节为 `0x11` 的 5 字节位置，按 `(imm32 - 当前位置 + 0x401000)` 改写，最后 `jmp 0x12d0`。

所以 **OEP = 0x4012d0**，真正的代码在解压后的 `DAS0` 里。

### 3.4 直接运行：exit 0，一个字都不输出

```
MidMath.exe  ->  exit code 0，stdout 空，stderr 空
```

这不是崩溃，也不是要参数。后面会看到，它是因为"随机游走的和没超过阈值"，所以什么也没打印。

既然静态解包要复刻自改字节和重定位，性价比不高，改走动态内存 dump：把"跳 OEP"那条指令 patch 成死循环，进程就会**停在解压与重定位都已完成、但还没进 OEP** 的时刻。

```python
off = 0x57300 + (0x2422cf - 0x242100)   # 文件偏移 0x574cf
assert b[off] == 0xE9                   # 原本是 jmp 0x12d0
b[off], b[off+1] = 0xEB, 0xFE           # 改成 jmp $（原地打转）
```

然后起进程、`OpenProcess` + `ReadProcessMemory` 抓 `0x400000` 起的镜像（这个 PE 没开 DYNAMICBASE，基址固定）：

```
[*] pid = 32220  alive = True
[*] module magic: b'MZ'
[OK] dumped 2375680 bytes -> dump_img.bin
[*] OEP bytes @0x401000: 83 ec 1c 8b 44 24 20 8b 00 8b 00 3d 93 00 00 c0
```

2 375 680 字节正好等于 `0x244000`，即"RVA = 文件偏移"的平坦镜像，后面所有地址都能直接用。

### 3.5 dump 出来的字符串终于能读了

在镜像里扫可打印串，`0x4b10e8` 附近一段非常说明问题：

```
0x4b10e8  b'rb'        <- fopen 的模式
0x4b10eb  b'out'       <- 输入文件名
0x4b10ef  b'%d'        <- 读数字的格式
0x4b10f4  b'DASCTF{path_16-bit_md5_lowercase_encrypt}'
```

整份镜像里 `DASCTF` 只出现这一次，而且字符串里没有任何 `%d` / `%s` 占位符——说明它就是**被原样打印的常量**，不是运行期拼出来的。壳里那些 `_low` / `cas` / `encrypt` 碎片，只是压缩数据里恰好的可见字符，不是离散的 flag 片段。

### 3.6 `main` 的真身：读数塔 → 随机游走 → 比阈值

符号表虽然残缺，但引用 `0x4b10f4` 的地方只有一处（`0x401566`），顺着往回读就能拿到完整逻辑。`main` 在 `0x401410`，等价 C 大致是这样：

```c
int arr[500][500];            // 全局，0x4f8020
int pick[501];                // 全局，0x5ec260，记录每层选左还是选右
FILE* fp = fopen("out", "rb");
int i = 1, j = 1;
while (fscanf(fp, "%d", &arr[i][j]) != EOF) {   // 三角形状逐个读
    if (i == j) { j = 1; i++; } else { j++; }
}
i--;                                     // 多涨了一行，退回来
int col = 1;
int sum = arr[1][1];                     // 0x4f87f4
for (int lv = 1; lv <= i; lv++) {
    int c = rand() % 2 + 1;              // 1 或 2
    pick[lv] = c;
    if (c == 1) sum += arr[lv + 1][col];         // 左下
    else      { sum += arr[lv + 1][col + 1]; col++; }  // 右下
}
if (sum > 0x65c270) printf("DASCTF{path_16-bit_md5_lowercase_encrypt}");
```

几个细节可以对着反汇编核：

| 位置 | 现象 | 含义 |
|---|---|---|
| `0x40146d` | `add $0x4f8020,%eax`，索引 `i*500+j` | 数塔存成 500×500 定长二维数组 |
| `0x4014e1` | `cltd / shr 31 / add / and 1 / sub / add 1` | 标准 `x%2` 定点数化，再 `+1`，取值只有 1、2 |
| `0x4014fb` | `mov %edx,0x5ec260(,%eax,4)` | 每层的选择被记下来（作者本来想让你输出"路径"） |
| `0x401559` | `cmpl $0x65c270,0x20(%esp)` | 判定用的阈值是**立即数**，不是变量 |
| `0x401563` | `movl $0x4b10f4,(%esp); call printf` | 只有一个参数，就是那条常量字符串 |

注意 `rand()` **没有 `srand` 播种**，所以每次运行走的是同一条固定路径，程序行为是完全确定的。

### 3.7 阈值 = 最大路径和 − 1

阈值是 `0x65c270 = 6 668 912`。对数塔做一次 DP：

```python
best[i][j] = max(best[i-1][j-1], best[i-1][j]) + a[i][j]
mx = max(best[499])
```

```
[*] 行数 = 500，首行 1 个数，末行 500 个数
[*] 数字总数 = 125250，min = 1，max = 20000，均值 = 8582.028
[OK] 最大路径和 = 6668913 = 0x65C271
[i] exe 里的阈值常量 0x65C270 = 6668912
[i] 最大路径和 - 阈值 = 1  → 只有走到最优路径才可能满足 sum > 阈值
```

`0x65C271` 比阈值大 1。又因为"图上的路径和不可能超过最优解"，`sum > max-1` 等价于 `sum == max`——**判定条件被写成了"随机游走必须刚好踩中 DP 最优路径"**。这就是本题的名字 MidMath 的真正含义：壳只是外壳，内核是一道数塔 DP。

那默认随机游走走到哪儿？未播种的 MSVCRT `rand()`（seed=1）复现出来：

```
[i] 未播种 rand() 前 16 步 = [2, 2, 1, 1, 2, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2]
[i] 该随机游走路径和 = 4408998，是否 > 阈值：False
```

440 万和 667 万，差得远——所以直接双击跑，永远看不到 flag。这也解释了 3.4 节那次"exit 0、零输出"。

### 3.8 动态验证：换掉 `out` 让条件成立

阈值是常量、`out` 是外部数据，那就把 `out` 换成"随便怎么走和都很大"的三角形：500 行、每行 i 个 `20000`。这样任何一条路径的和都是 `500*20000 = 10 000 000 > 6 668 912`。

```
written  ...\mm_test\out
exit=0
STDOUT=[DASCTF{path_16-bit_md5_lowercase_encrypt}]
STDERR=[]
```

真 exe 把 flag 原样打出来了，与静态结论完全一致：flag 是常量，判定是数塔最优路径。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| 壳的段名伪装 | 把 `UPX0/1/2` 改名为 `DAS0/1/2`，段数与"磁盘大小 0 的虚拟段"特征不变 | 拖时间、骗自动化识别 | 任何加壳样本的第一识别步骤 |
| aPLib（aP_depack） | 位流里"literal 串 + gamma 编码的 (offset,length)"，用 `add ebx,ebx` 取位 | 作者的压缩算法本身 | UPX 的 NRV2B 系列、嵌入式 bootloader |
| 自修改压缩流 | 解压前把压缩流某 4 字节改成固定值，解完还原 | 让"磁盘字节直接解"必然失败 | 反 dump、反特征提取类壳 |
| 标记式重定位 | 扫 `E8/E9 11` 的 5 字节点，按 `imm32 - pos + base` 修正 | 解压出来的镜像需要重定位 | 手工脱壳、内存镜像修复 |
| 内存 dump | patch 成 `jmp $` 停在 OEP 前，再 `ReadProcessMemory` | 免去复刻壳的全部细节 | 所有"壳改过字节"的样本 |
| 数塔 DP | `best[i][j] = max(左上, 正上) + a[i][j]` | 判定阈值正是最优解减一 | 算法题、路径规划、题目里的"数学内核" |

## 五、踩坑与陷阱

1. **`DAS0` 段磁盘大小为 0**，一开始很容易误判成"资源段为空"；实际它是解压目标区，真代码在内存里。
2. **不要用磁盘字节直接解 aPLib**。`0x5eca7c` 处那 4 个字节 `21 47 F5 8A` 是运行期写进去的，静态解一定错位。
3. **`DAS1+0x15` 前面那 21 字节不是压缩数据**，是壳自己的头；从 `0x5eb000` 开始解就会全错。
4. **覆盖层里的符号表是截断的**（21794 个符号只落盘了 8000 多个），别指望靠它找 `main`；改用"引用字符串地址"反查更快。
5. **`0x65c270` 是立即数不是全局变量**。用 xref 找它只会找到比较指令本身，别以为它在 `.data` 里被别处赋过值。
6. **`rand()` 没播种**。几次运行结果完全一样，所以"多试几次就好了"是错觉。
7. 阈值是 `最大路径和 - 1` 这种"差一"设计，说明作者故意留了"必须最优"的语义；真按"比阈值大一点"去理解会绕远。

## 六、赛场 20 分钟行动清单

1. `out` 看一眼形状 → 判定数塔，10 秒。
2. `objdump -h` / 导入表 → 判定"自定义壳"，2 分钟。
3. 入口反汇编 → 认出 aPLib 与 `esi=0x5eb015`、`edi=0x401000`，3 分钟。
4. 直接跑一次，确认 `exit 0` 无输出，记下"程序能正常结束"，1 分钟。
5. 放弃静态解包，改 patch `jmp OEP` → `jmp $`，起进程 dump 内存，5 分钟。
6. dump 里 `DASCTF` + `out` + `%d` 一把捞出来，顺 `0x4b10f4` 的 xref 定位 `main`，4 分钟。
7. 读 `main` 抓三件事：读 `out` 的索引式、`rand()%2+1` 的走法、`cmpl $0x65c270`。
8. 数塔 DP 算最大路径和，发现正好比阈值大 1，2 分钟。
9. 换 `out` 为全 20000 复跑，拿到 flag 互证，2 分钟。

> 超过 25 分钟还卡在"复刻壳的自改字节 + 重定位"上就换动态 dump；这题的壳是干扰项，DP 才是内核。

## 七、附件与脚本

- 原始附件：`files/tempdir/REVERSE附件/MidMath.zip` → `MidMath_unzip/MidMath.exe`、`MidMath_unzip/out`。
- `src/zj10/midmath_dp.py`：读 `out` 做数塔 DP、算最大路径和、复现未播种 `rand()` 的走法。用法：
  `python midmath_dp.py <out 路径>`，输出最大路径和 `6668913`、阈值 `6668912`、随机游走 `4408998`。
- 参赛目录里还留着当时的侦察脚本：`solve/probe_out.py`（统计 `out`、试 MSVC `rand()%20000` 偏置与"Pascal mod p"假设）、`solve/probe_regions.py`（各段熵）、`solve/coff_probe.py`（COFF 符号表）、`solve/patch_hang.py`（patch 成 `jmp $`）、`solve/dump_mem.py`（`ReadProcessMemory` 抓镜像）。
- 复现顺序：`patch_hang.py` → `dump_mem.py` → 在 `dump_img.bin` 里定位 `0x4b10f4` → `midmath_dp.py` → 换 `out` 复跑。
