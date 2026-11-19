# 第 7 题 · SNOW — Writeup

> **本合集路径说明**：本篇原属 `CTF-WP\07-SNOW`，正文里写的 `solve/xxx.py`、`files/xxx` 是**原工程相对路径**；脚本已留在原工程 `solve\` 下（附件 `files\tempdir\CRYPTO附件\task.zip` 未随迁，需要时去原工程取）。

> DASCTF 题集（flag 前缀 `DASCTF{}`） · 分类：Crypto / 流密码 · 难度：★★★★☆

| 项目 | 内容 |
|---|---|
| 题目名 | SNOW |
| 分类 | Crypto（流密码、LFSR + FSM 状态恢复） |
| 附件 | `task.zip` → `task/snow.py`（SNOW 风格的 16 字 LFSR + 3 字 FSM 实现）、`task/task.py`（含 88 个密文字与 `hack()` 的 10 个泄漏值） |
| 一句话 | 流密码的密钥流一旦漏出前 44 字、再叠加 `hack()` 漏出的几个 LFSR/FSM 状态，就能代数反解出 512 bit LFSR 与 3 字 FSM，然后重放整条流 |
| 结果 | `DASCTF{2bfc1bd3-740e-4b3f-ab9f-9587b1d47209}` |

**最终答案**

```
DASCTF{2bfc1bd3-740e-4b3f-ab9f-9587b1d47209}
```

[TOC]

## 一、题目长什么样（先建立直觉）

附件解压出两个文件。`snow.py` 是一个完整的 SNOW 家族流密码实现：16 个 32 bit 字的 LFSR、3 个 32 bit 字的 FSM，两个 S 盒 `sr`／`sq`，`mul_alpha`／`div_alpha` 做 GF(2⁸) 上的 α 乘，`initialize()` 用 32 轮初始化模式把 key/iv 搅进状态，`generate_keystream()` 才进入密钥流模式。

`snow.py` 最后那个 `hack()` 才是题眼：

```python
def hack(self):
    print(self.R1[2],self.R2[2],self.R3[2],self.S[2],self.S[3],self.S[6],self.S[7],self.S[8],self.R1[5],self.R1[7],sep=",")
```

它把**第 2 轮的完整 FSM 状态**（`R1[2],R2[2],R3[2]`）、**5 个 LFSR 字**（`S[2],S[3],S[6],S[7],S[8]`）、以及两轮 FSM 首字（`R1[5],R1[7]`）直接打印出来。这不是漏洞，这是“设计好的漏洞”。

`task.py` 只有 20 行，逻辑一目了然：

```python
key = [random.getrandbits(32) for _ in range(4)]
iv  = [random.getrandbits(32) for _ in range(4)]
s = Snow(key, iv)
gift  = b"the quick brown fox jumps over the lazy dog\n"   # 44 字节，明文已知
plain = gift + flag
key_stream = s.generate_keystream(len(plain))
C = [i ^ j for i, j in zip(plain, key_stream)]
print(C)
s.hack()
```

注意 `zip(plain, key_stream)` 把**一个明文字节和一个 32 bit 密钥流字**配对异或，所以 `C` 是 88 个 32 bit 大整数，不是字节。`task.py` 的注释里把两条输出都贴上了：`C` 的 88 个数，和 `hack()` 的 10 个数。所以题目的形状很清楚：**已知明文给了 44 字节 ⇒ 密钥流前 44 字全泄漏；还差后面 44 字的密钥流，而 `hack()` 给的那 10 个状态值就是补齐它的钥匙。**

## 二、思路总览

先把结论说完：这题**不需要**恢复 key/iv，也不需要破解 LFSR 的线性递推，只需要**把下标约定抠清楚，然后照着 10 个泄漏值列 11 步方程**。

```
1) gift 44 字节  ->  kks[i] = C[i] ^ gift[i]          (i = 0..43)  已知密钥流
2) hack() 给 10 个值  ->  完整 FSM@2 + 5 个 LFSR 字 + R1[5], R1[7]
3) 从 generate_keystream 抠出约定：ks[i] = (S[i+15] + R1[i]) ^ R2[i] ^ S[i]
4) 用约定把泄漏量变成方程，逐个解出 S[9] S[10] S[11] S[12] S[13] S[14] S[15] S[16] S[17] S[18] S[19] S[20] S[21] S[22] S[23]
   -> 凑齐 L0 = S[0..15] 和 FSM0 = (R1[0], R2[0], R3[0])
5) replay 88 字密钥流 -> plain = C ^ ks -> flag
```

第 4 步用到两类关系，缺一不可：
- **FSM 侧**：`R1[i+1] = R2[i] + (R3[i] ^ S[i+5])`、`R2[i+1] = s1(R1[i])`、`R3[i+1] = s2(R2[i])`。正向可推，反向要能求 `s1⁻¹`／`s2⁻¹`。
- **LFSR 侧**：`S[k+16] = PSI(S[k]) ^ S[k+2] ^ PHI(S[k+11])`，其中 `PSI(a)=(a<<8)^mul_alpha(a>>24)`、`PHI(c)=(c>>8)^div_alpha(c&0xff)`。这条递推式可以正着算，也可以反解出 `S[k+2]` 或 `S[k+11]`。

## 三、逐步复现

### 3.1 第一步：把下标约定钉死（全题最容易错的地方）

`generate_keystream()` 的 append 顺序很容易看错，抄错一处后面全崩：

```python
def generate_keystream(self, n):
    keystream = np.zeros(n, dtype=np.uint32)
    self.clock_fsm(self.lfsr[15], self.lfsr[5])     # 循环前先 clock 一次
    self.lfsr_keystream_mode()                      # 再移一次
    self.R1.append(self.fsm[0]); self.R2.append(self.fsm[1]); self.R3.append(self.fsm[2])   # -> *[0]
    for i in range(n):
        F = self.clock_fsm(self.lfsr[15], self.lfsr[5])
        self.R1.append(self.fsm[0]); self.R2.append(self.fsm[1]); self.R3.append(self.fsm[2])  # -> *[i+1]
        self.S.append(self.lfsr[0])                 # -> S[i]
        keystream[i] = F ^ self.lfsr[0]
        self.lfsr_keystream_mode()
```

由此得到两条**必须实测验证**的恒等式：

```
ks[i]      = (S[i+15] + R1[i]) ^ R2[i] ^ S[i]     # R1[i] 是第 i 轮 clock 之前的状态
R1[i+1]    = R2[i] + (R3[i] ^ S[i+5])
```

验证办法很土但可靠：随便取一组 key/iv，`generate_keystream(90)`，然后逐项比对（`S` 要有 90 项以上才够查 `S[i+15]`）：

```python
M = 0xFFFFFFFF
for i in range(4):
    assert (((S[i+15] + R1[i]) & M) ^ R2[i] ^ S[i]) == ks[i]
for i in range(6):
    assert ((R2[i] + (R3[i] ^ S[i+5])) & M) == R1[i+1]
```

实测 4 项／6 项全部成立。**先验约定，再谈解方程**——这题后面所有的代数式都建立在这两行上。

### 3.2 第二步：把 `hack()` 的泄漏量翻译成"已知量清单"

`task.py` 注释里的第二行就是泄漏值（真实值）：

```
834501734, 940247165, 2078728259, 483907438, 1102712410,
3110955761, 3016462560, 871310805, 1334672645, 1102778698
```

按 `hack()` 的参数顺序对号入座：

| 位置 | 变量 | 含义 |
|---|---|---|
| 1~3 | `R1[2], R2[2], R3[2]` | **第 2 轮的完整 FSM 状态**（白送） |
| 4~8 | `S[2], S[3], S[6], S[7], S[8]` | 5 个 LFSR 字，分两段（2,3 与 6,7,8） |
| 9 | `R1[5]` | 用来反解 `S[9]` |
| 10 | `R1[7]` | 用来反解 `S[11]` |

`len(C) = 88`，`gift` 44 字节，所以 flag 恰好 44 字节，需要 `keystream[44..87]`。

### 3.3 第三步：11 步代数链（本题的全部内容）

核心是把"FSM 前推一格"和"LFSR 递推"交替使用，每步都消掉一个未知量。代码里的 `step()` 就是 FSM 前推：

```python
def step(R1, R2, R3, s5):
    return ((R2 + (R3 ^ s5)) & M, s1(R1), s2(R2))

def g(a, b, c):                       # LFSR 递推 S[k+16] = g(S[k], S[k+2], S[k+11])
    return PSI(a) ^ (b & M) ^ PHI(c)
```

链条如下（`wN` 即 `S[N]`）：

| 步 | 方程 | 解出 |
|---|---|---|
| 1 | `F3=step(F2, S[7])`、`F4=step(F3, S[8])` | FSM@3、FSM@4 |
| 2 | `S[17] = ((ks[2]^S[2]) ^ R2[2]) - R1[2]` | S[17] |
| 3 | `S[18] = ((ks[3]^S[3]) ^ R2[3]) - R1[3]` | S[18] |
| 4 | `S[9] = (R1[5] - R2[4]) ^ R3[4]` | **S[9]** |
| 5 | `S[11] = (R1[7] - s1(R1[5])) ^ s2(R2[5])` | **S[11]** |
| 6 | `S[22] = g(S[6],S[8],S[17])`；`R2[7]=(ks[7]^S[7])^(S[22]+R1[7])` | S[22]、R2[7] |
| 7 | `R1[6] = s1⁻¹(R2[7])`，`S[10] = (R1[6]-R2[5]) ^ R3[5]` | R1[6]、**S[10]** |
| 8 | `S[23]=g(S[7],S[9],S[18])`，`R1[8]` 由 `ks[8]` 反解，`S[12]=(R1[8]-R2[7])^R3[7]` | S[23]、**S[12]** |
| 9 | `S[1] = PSI⁻¹(S[17] ^ S[3] ^ PHI(S[12]))` | S[1] |
| 10 | 反推 FSM@1：`R1[1]=s1⁻¹(R2[2])`、`R2[1]=s2⁻¹(R3[2])`、`R3[1]=(R1[2]-R2[1])^S[6]`；再 `S[16]` | S[16] |
| 11 | `S[0]=PSI⁻¹(S[16]^S[2]^PHI(S[11]))`，`S[21]`、`S[5]=PSI⁻¹(...)`、`S[15]`、`S[20]`、`S[4]`、`S[13]`、`S[19]`、`S[14]` 依次收尾 | 全部 16 字 |

真实运行打印的中间量（可用于对拍）：

```
len(C) = 88，其中 gift 44 字节，flag 44 字节
hack() = (834501734, 940247165, 2078728259, 483907438, 1102712410,
          3110955761, 3016462560, 871310805, 1334672645, 1102778698)
S17 = 760f3918
S18 = dd06abe5
S22 = 1df6d70f
S23 = df2b5730
```

这四组值是最容易抄错的地方：它们的输入只有 `ks[0..8]` 和泄漏量，随便一个下标偏移都会算成完全不同的数，所以对不上就别往下走了。

### 3.4 第四步：先在合成实例上自检，再打真实数据

**这题不能跳过自检**。合成的意义是：自己挑 key/iv，`hack()` 的 10 个值和真实的 `S[0..15]`／`FSM0` 都知道，链子写错立刻能看见。

```
== A. s1 / s2 / PSI / PHI 求逆自检 ==
  [OK] 四个映射的双向往返全部通过（300 次随机往返）
== B. 合成实例（完整字版 s1/s2）==
  L0 还原 : True
  FSM0 还原 : True
  密钥流重放 : True
```

三个 `True` 之后才允许打真实数据。这一步的坑见第五节：**合成实例必须用"完整 32 位版"的 s1/s2**，否则会跟题目泄漏量对不上。

### 3.5 第五步：重放整条流，取 flag

状态到手，重放就是照抄 `generate_keystream()` 的循环：

```python
def replay(L0, F0, n):
    L, F, out = L0[:], F0, []
    for _ in range(n):
        out.append(ks_word(L, F))          # (L[15] + F[0]) ^ F[1] ^ L[0]
        F = step(*F, L[5])                 # FSM 前推，s5 = lfsr[5]
        L = shift(L)                        # LFSR 移一格，新字 = g(L[0], L[2], L[11])
    return out
```

真实运行输出：

```
  gift 段还原 : True
  明文 = b'the quick brown fox jumps over the lazy dog\nDASCTF{2bfc1bd3-740e-4b3f-ab9f-9587b1d47209}'
  flag = DASCTF{2bfc1bd3-740e-4b3f-ab9f-9587b1d47209}
```

`gift 段还原 : True` 这一句含金量很高：恢复状态只用了 `ks[0..8]`（9 个字），而重放能把 `ks[9..43]` 也对上，等于额外用 **35 字 = 1120 bit** 做了验证。加上明文字节全部可打印、长度精确 88（44 + 44），flag 可以签字。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| 流密码的"密钥流即明文" | `C = P ^ KS`，知道 `KS` 就等于知道 `P` | `gift` 44 字节直接把前 44 字密钥流送出来 | 所有 XOR 型流密码（RC4、ChaCha、SNOW、ZUC） |
| LFSR（16 字 × 32 bit） | 每拍移一格，新字由 `S[k]`、`S[k+2]`、`S[k+11]` 决定 | 它提供了 `S[k+16]` 的线性递推，可以正算也能反解 | SNOW/ZUC 系、LFSR 序列分析、BM 算法 |
| FSM（3 字） | `R1 += R2 + (R3^s5)`，`R2/R3` 走 s1/s2 | 它把 LFSR 输出变成非线性密钥流；`hack()` 泄了完整 FSM@2 | SNOW 2.0/3G、Grain、Trivium |
| `PSI` / `PHI` 是 GF(2) 线性 | `PSI(a)=(a<<8)^mul_alpha(a>>24)`、`PHI(c)=(c>>8)^div_alpha(c&0xff)` | 线性 ⇒ 可以写成 32×32 位矩阵求逆，反解 `S[k]`／`S[k+11]` | 任何域乘法/移位混合的 LFSR |
| `s1`/`s2` 是**非线性**双射 | `MixColumns(S 盒逐字节)`，AES 式结构 | 求逆必须"线性混合矩阵求逆 + S 盒逆表"两步走，不能当线性函数 | AES、SNOW、任何 SPN 结构 |

## 五、踩坑与陷阱

1. **把 `s1`/`s2` 当成 GF(2) 线性函数求逆（最大的坑）**：早期探针 `solve/_probe.py` 用 `cols_of(s1)` 取 32 个基向量像、再 `inv_cols()` 求逆，结果直接崩在 `ValueError: singular at col 7`，实测 `s2` 的"秩"只有 28。原因是 `sr`/`sq` 是**非线性 S 盒**，`f(1<<i)` 根本不构成线性映射的列。正确做法是拆开：`s1 = MC ∘ S盒`，`MC` 用 GF(2) 矩阵求逆、S 盒用逆表。

2. **numpy 版本差异让 `s1`/`s2` 悄悄退化**：`snow.py` 里 `r0 = (...) & 0xff` 得到的 `r0` 是 `np.uint8`，末尾 `(r0 << 24) | (r1 << 16) | (r2 << 8) | r3` 在 **numpy 2.x 的 weak promotion** 下会左移清零。实测本机 `s1(0x00010203)` 只返回 `0x70`（只有最低字节）。而题目泄漏量里 `R2[2] = 940247165` 是完整 32 位——说明**作者环境是完整字输出**。所以本地复现必须用完整 32 位版 `s1`/`s2`（本篇用子类猴补丁），否则合成实例和真题根本不是一个密码。

3. **`R1[i]` 的语义错一位**：`R1[i]` 是第 `i` 轮 clock **之前**的状态（循环里 append 的是 clock 之后的值，所以 `R1[i]` 实际由第 `i-1` 轮写入）。如果按"`R1[i]` 是 clock 之后"理解，`ks[i]` 会整体错一格，解出来的 `S[9]`…`S[23]` 全是垃圾值——而且看起来"有解"，最难查。用 3.1 的两条恒等式先验一遍。

4. **`replay` 里的取字顺序**：`ks_word` 必须用**当前** `L` 和**当前** `F`，先取字再推 `F`／移 `L`。反过来写会让整条流平移一个字，`gift` 段校验立刻 False（这反而是好事——校验救了你）。

5. **手抄 `C` 的 88 个数**：注释里那串数字很长，手抄错一位结果就是乱码。用正则从文件里取 `C` 与 `leak`（以 `# [` 开头的那行是 `C`，逗号数为 9 的那行是泄漏值）。

6. **以为要恢复 key/iv**：`key`/`iv` 各 4 个 32 bit 随机字，`initialize()` 做了 32 轮非线性初始化，反推它比直接恢复运行态难得多。**`hack()` 已经把运行态送到手里了，别绕远路。**

## 六、赛场 20 分钟行动清单

1. 读 `snow.py` 的 `generate_keystream()` 和 `hack()`：**先写死两条下标恒等式并用随机 key/iv 验一遍**。3 分钟，省后面 30 分钟。
2. 从 `task.py` 抠出 `C`（88 个）和 `hack()` 的 10 个值，`len(C) - 44 = flag 长度`。1 分钟。
3. 算 `ks[0..8]`，先按 FSM 前推算出 `FSM@3/4`，再用 `R1[5]`、`R1[7]` 拿 `S[9]`、`S[11]`。—— 这一步能出数就说明约定对了。
4. 用 LFSR 递推补 `S[17]`…`S[23]`，反推 `FSM@1`、`FSM@0`，凑齐 `L0` + `FSM0`；再按 3.3 收尾取齐 16 字。
5. **合成实例自检**（自己造 key/iv，比 `L0`、`FSM0`、密钥流三项）。三项全 True 再打真题。
6. 重放 → `plain`，先看 `gift` 段是否还原，再看 flag 格式。
> 超过 20 分钟没进展就跳题。这题的判别信号很硬：**`S[17]`/`S[18]` 算出来对不对，一试就知道链子通不通。**

## 七、附件与脚本

原始附件：`files\tempdir\CRYPTO附件\task.zip` → `task_unzip\task\{snow.py, task.py}`（只读，全程未改动）。

| 脚本 | 干什么 | 状态 |
|---|---|---|
| `files/.../task/snow.py`、`task/task.py` | 题目给的密码实现（含 `hack()`）与出题脚本（注释里带 `C` 和泄漏值） | 只读 |
| `solve/_probe.py` | 历史探针：验证线性性、试图用 GF(2) 线性法求 `s1`/`s2` 的逆 | **崩**（`singular at col 7`），保留作为反例 |
| `solve/01_state_recovery.py` | 本篇正式解法：求逆自检 → 合成实例验证 → 打真题 | 跑通，产出 flag |

跑法（Python 3.12 + numpy，先设 UTF-8）：

```powershell
$env:PYTHONIOENCODING="utf-8"
python solve\01_state_recovery.py
```

脚本结构对应本篇的五步：`A` 段验四个映射的双向可逆，`B` 段用 `SnowFixed`（完整 32 位版 `s1`/`s2`）跑合成实例并核对 `L0`/`FSM0`/密钥流，`C` 段从 `task.py` 正则取数、走 11 步链、重放 88 字、打印明文与 flag。
