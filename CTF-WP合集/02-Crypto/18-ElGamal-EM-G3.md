# DASCTF · ElGamal「EM-G3」— Writeup

> DASCTF（incident `EM-G3-2026-1018`，group `RFC3526-14`）· 分类：Crypto · 难度：★★☆☆☆

| 项目 | 内容 |
|---|---|
| 题目名 | EM-G3（`algorithm: ElGamal-2048`，`group: RFC3526-14`） |
| 分类 | Crypto — ElGamal / 弱随机数导致的小私钥空间 |
| 附件 | `params.json`（2,942 B，给 `p`／`g`／`public_key_h`／`ciphertext.c1`／`ciphertext.c2`）；现场脚本 `solve_elgamal.py`（5,636 B）、`check.py`（2,774 B）、`decrypt.py`（569 B） |
| 一句话 | 2048 位安全素数是障眼法：参数完全正确，坏掉的是私钥指数 `x` 的熵——`x = 139`，只有 8 bit，于是在 `x` 的小范围上跑 BSGS 就把 ElGamal 拆了。 |
| 结果 | 已拿下（solved） |

**最终答案**

```
DASCTF{b4210c04-15d2-4ed8-be4d-742595e0cdca}
```

## 一、题目长什么样（先建立直觉）

`params.json` 是标准 ElGamal 三件套加一组密文：

```json
{
  "incident": "EM-G3-2026-1018",
  "algorithm": "ElGamal-2048",
  "group": "RFC3526-14",
  "p": "0xffffffffffffffffc90fdaa2...68ffffffffffffffff",
  "g": "0x48d408ae69bcb4aa...aa10edc",
  "public_key_h": "0xaad5b70b0f73b754...dd55abee1a8",
  "ciphertext": { "c1": "0xc03872ba41ef41c9...fd9fdd811a", "c2": "0x70eb6418da667832...293bc40919064d4" }
}
```

一眼能认出来的东西：`p` 的十六进制以 `ffffffffffffffffc90fdaa2…` 开头、以 `…8aacaa68ffffffffffffffff` 结尾——这是 **RFC 3526 的 2048 位 MODP group 14** 常量，不是“随便一个大素数”。`g` 有 2043 位，`h`、`c1` 都是 2048 位，`c2` 是 2047 位。

真正该盯的是 `note` 的最后一句：

> The private exponent came from the same broken RNG stage; **entropy is measured in bits, not bytes**.

前半句说“私钥指数来自同一个坏掉的 RNG 阶段”，后半句在提醒你：这里的熵是**比特**为单位，不是字节。这句话就是整道题的钥匙——后面会看到实际值正好是 8 bit。

## 二、思路总览

1. **参数体检**：验证 `p` 是不是素数、是不是真等于 G14、`p-1` 的分解、`g` 与 `h` 的阶。目的是把“参数被动过手脚”这类假设全部排除掉。
2. 排除法结论：`p` 安全素数（`p-1 = 2q`，`q` 素数），`ord(g) = q`，`h` 与 `g` 同属二次剩余子群 → Pohlig-Hellman、小子群攻击、参数造假全部走不通。
3. 回到 `note`：私钥熵只有几 bit → 问题从“求 2048 位群里的离散对数”退化成“**求一个很小范围内的离散对数**”。
4. 用 BSGS 在 `x < 2^16` 里搜，瞬间命中 `x = 139`，`pow(g,x,p) == h` 复核通过。
5. 代回解密公式 `m = c2 · (c1^x)^{-1} mod p`，把大整数转字节即得 ASCII flag。

## 三、逐步复现

### 3.1 第一步：参数体检（把常规攻击面全排掉）

`check.py` 的实测输出（`python check.py`，总耗时 1.41 s，其中两次素性测试各约 0.6 s）：

```
p bits      : 2048
p == G14    : True
g bits      : 2043  h bits: 2048
c1,c2 bits  : 2048 2047
g in [2,p-2]: True  h in [2,p-2]: True
p prime     : True 0.61s
q prime     : True 0.59s  (p-1)/2
p-1 factor 2^1 * odd
g^q mod p   : 1 (order q)
h^q mod p   : 1 (quadratic residue)
legendre same: True  -> consistent
BSGS(2^20)  : 139 0.01s
```

逐行读：

| 输出 | 含义 | 排掉了什么攻击 |
|---|---|---|
| `p == G14: True` | `p` 与 RFC3526 group 14 常量逐字节相同 | 参数被替换／换成小素数 |
| `p prime: True`、`q prime: True`、`p-1 factor 2^1 * odd` | `p-1 = 2q`，安全素数 | `p-1` 光滑 → Pohlig-Hellman 快速分解 |
| `g^q mod p = 1` | `ord(g) \| q`，`g` 落在 q 阶子群 | `g` 是整群生成元这类“结构异常” |
| `h^q mod p = 1`、`legendre same: True` | `h` 与 `g` 同处二次剩余子群 | 小子群混淆／`h` 不在 `⟨g⟩` 里 |

结论很干脆：**参数一个毛病都没有**。这题要考的不是“参数写错”，而是随机数。这一步不能省——如果不先做，后面会一直在“是不是 `p` 被换了”上打转。

### 3.2 第二步：为什么 2048 位下“正经”解不了

ElGamal 的结构是 `c1 = g^k mod p`、`c2 = m · h^k mod p`、`h = g^x mod p`。要求 `m`，得先知道 `x`（或 `k`），也就是要解一次离散对数。

反过来看 `q` 的规模：`p` 是 2048 bit，`q = (p-1)/2` 就是 **2047 bit**。通用的离散对数解法（BSGS、Pollard rho、Pollard kangaroo）复杂度都是 `O(√N)`，`√q ≈ 2^1023`。这个数字和“暴力破 AES-128”不在一个量级上——它是**完全不可做**，不是“算久一点”。

而 `p-1 = 2q` 这个结构恰恰是安全素数存在的意义：

- Pohlig-Hellman 会把你打回两个子问题，模 2 的那部分平凡，模 `q` 的那部分仍是 2047 位，等于没帮你；
- 想让 `p-1` 光滑来加速，前提是 `p-1` 有很多小因子，而这里只有 `2` 和 `q`。

所以“在 2048 位安全素数下解离散对数”这条路是死的，题目必然在别处漏了东西。

### 3.3 第三步：弱点在私钥的熵，不在群

回到 `note`：`entropy is measured in bits, not bytes`。这句话两种读法，差别巨大：

| 读法 | 私钥空间 | 可行性 |
|---|---|---|
| 8 **字节** = 64 bit | `x < 2^64` | kangaroo 约 `2^32` 步，纯 Python 不现实 |
| 8 **比特** | `x < 2^8 = 256` | 几十步就够 |

出题人写的是 `bits`。实测结果站在“比特”这边：`x = 139`，`bit_length = 8`——**熵正好 8 bit**。

于是问题变成“已知 `h = g^x mod p` 且 `x < 2^16`，求 `x`”。这不是 2048 位群上的 DLP，而是**范围受限的 DLP**，代价只跟范围有关，跟群多大无关。

### 3.4 第四步：BSGS 命中 `x = 139`

BSGS（baby-step giant-step）把 `x = i·m + j` 拆开，先存 `g^j`（`j < m`），再用 `h·(g^{-m})^i` 去表里撞。`N` 是搜索上界时，时空都只要 `O(√N)`：

```python
def bsgs(g, h, p, n):
    m = math.isqrt(n) + 1
    table, e = {}, 1
    for j in range(m):                      # baby steps: 存 g^j
        table.setdefault(e, j)
        e = e * g % p
    g_inv_m = pow(pow(g, m, p), -1, p)      # giant steps: 每次乘 g^-m
    gamma = h
    for i in range(m + 1):
        j = table.get(gamma)
        if j is not None:
            x = i * m + j
            if x < n and pow(g, x, p) == h:  # 复核, 避免 BSGS 误报
                return x
        gamma = gamma * g_inv_m % p
    return None
```

`n = 2^16` 时 `m = isqrt(65536) + 1 = 257`，也就是 257 次小步乘法 + 最多 258 次大步乘法。`check.py` 里 `BSGS(2^20)` 只用 **0.01 s** 就返回 `139`。

拿 `x` 做的第一件事必须是复核：

```
verify g^x == h : True
x bits          : 8  (x=139)
```

`solve_elgamal.py` 里复核做了两道：BSGS 返回前 `pow(g,x,p)==h`，`main()` 里再 `assert pow(g,x,p)==h`。原因见第五节——小范围 BSGS 有误报的坑。

### 3.5 第五步：代回解密公式

```python
s = pow(c1, x, p)              # c1^x = g^(kx)
m = c2 * pow(s, -1, p) % p     # m = c2 · (c1^x)^(-1)
b = m.to_bytes((m.bit_length() + 7) // 8, "big")
```

`decrypt.py`（把 `x = 139` 写死，只做验证）的真实输出：

```
verify g^x == h : True
x bits          : 8  (x=139)
m bits          : 351
hex             : 4441534354467b62343231306330342d313564322d346564382d626534642d3734323539356530636463617d
plaintext       : DASCTF{b4210c04-15d2-4ed8-be4d-742595e0cdca}
```

`hex` 开头 `4441534354467b` 就是 ASCII 的 `DASCTF{`，`7b`／`7d` 是 `{`／`}`——明文没做任何填充，直接就是 flag 字符串，`bit_length = 351` 也符合“44 个字符”这个量级。

### 3.6 第六步：把整条链写成一条命令

`solve_elgamal.py` 是自包含的：参数内嵌，只跑 `python solve_elgamal.py` 就能出结果；也支持读外部参数 `python solve_elgamal.py params.json`。实测（`params.json` 版本，0.14 s）：

```
[*] p = 2048 bit, g = 2043 bit, h = 2048 bit
[*] searching x < 2^16  ->  139
[+] private exponent x = 139  (bit_length = 8, i.e. entropy 8 bits)
[+] plaintext hex : 4441534354467b62343231306330342d313564322d346564382d626534642d3734323539356530636463617d
[+] plaintext     : DASCTF{b4210c04-15d2-4ed8-be4d-742595e0cdca}
```

脚本里的搜索是**逐级升档**的：`2^16 → 2^24 → 2^32`，命中就停。本题第一档就中了，后两档根本没进——这是留给“熵比预期大一点”的题用的，不是这里必须跑的。真到 `2^40` 以上，才该换 Pollard kangaroo（省内存）；而 `2^32` 以内 BSGS 用 `m = isqrt(2^32) + 1 ≈ 65537` 的字典完全够。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| ElGamal 加密 | `c1 = g^k`、`c2 = m·h^k`，`h = g^x` | 题目给的就是 `(c1, c2)` 与 `h` | 所有 ElGamal／DH 派生题 |
| 范围受限 DLP | 已知 `h = g^x` 且 `x < N`，求 `x` | 复杂度只跟 `N` 有关，`O(√N)` | 弱随机数、时间戳种子、`low-entropy nonce` |
| BSGS | `x = i·m + j`，先存小步再撞大步 | `2^16` 范围只需 257 步，秒出 | 任何“指数很小”的场景 |
| 安全素数 `p = 2q+1` | 保证大素数阶子群 | 它保证了**通用** DLP 不可做，也保证了本题没有别的捷径 | 判断“参数是不是被动过手脚” |
| Pohlig-Hellman | 按 `p-1` 的小因子分解 DLP | 这里 `p-1` 只有因子 2 和 `q`，帮不上忙 | 反过来：`p-1` 光滑时是致命弱点 |
| 小子群攻击 | `h` 落在低阶子群时可枚举 | 这里 `h^q = 1`，与 `g` 同子群，无此问题 | 参数校验不严的 DH／ElGamal |
| 熵的单位 | bit 与 byte 差 8 倍指数 | `note` 明写 `bits, not bytes`，实际 8 bit | 所有“弱随机数”题的题干措辞 |
| 单组密文的信息量 | 一组 `(c1,c2)` 无法做 `k` 复用 | 没有第二组密文可比 `gcd(c1a-c1b, p)` | 多密文同 `k` 时才是另一个故事 |

## 五、踩坑与陷阱

1. **以为 `p` 被换过。** 2048 位、一看就是标准常量的 `p`，很容易怀疑“是不是拿了个合数冒充素数”。实际 `p == G14` 逐字节成立、`p` 与 `q` 都是素数——先花 1.4 秒体检，比在错方向上推理半小时划算。
2. **把 `bits` 读成 `bytes`。** 一旦按 8 字节（64 bit）去搜，`2^32` 量级的步数在纯 Python 里就跑不完，很自然地会得出“这题做不了”的错误结论。题干里 `entropy is measured in bits, not bytes` 是**明写的提示**，不是修辞。
3. **小范围 BSGS 会误报。** 表里 `g^j` 的碰撞、以及 `x = i·m + j` 超出预定范围，都会给出一个“看着像答案”的 `x`。脚本里两道 `pow(g,x,p)==h` 复核就是为这个准备的——`x = 139` 这么整的数字，第一反应就该是复核而不是庆祝。
4. **过度设计。** 一开始按 `2^40` 去设计 Pollard kangaroo（跳表、distinguished point、碰撞处理），代码量和出错概率都上去了，结果 `x` 只有 8 bit。先用 BSGS 从最小档试，是对的顺序。
5. **在单组密文上找“共用 k”。** `k` 复用要两组以上密文才能做 `gcd(c1a - c1b, p)`；这题只有一组 `(c1, c2)`，这条路一开始就不存在，别浪费时间。
6. **明文不是文本时别硬 `decode`。** 这里 `m` 转字节刚好是 ASCII，直接 `decode` 就行；如果 `bit_length` 不是 8 的倍数、或者字节不可打印，就要考虑填充／分块，而不是当成“解错了”。

## 六、赛场 20 分钟行动清单

1. 读 `params.json` 的元信息（`algorithm`／`group`／`note`），先把题干里的“提示句”摘出来（1 分钟）。
2. 跑参数体检：`p` 是否素数、`p-1` 分解、`ord(g)`、`h` 是否同子群（1～2 分钟）。
3. 体检全绿 → 别再碰参数，转去盯“随机数／指数范围／密文组数”（2 分钟）。
4. 按 `2^16 → 2^24 → 2^32` 逐级 BSGS，命中立刻 `pow` 复核（3 分钟）。
5. 代回 `m = c2·(c1^x)^{-1} mod p`，转字节看是不是 ASCII（2 分钟）。
6. 出不了 flag 就回头核对：是不是 `x` 误报、是不是要处理填充、是不是有多组密文没被用上（5 分钟）。

> 超过 15 分钟还停在“参数体检不通过”，说明这题的结构和标准 ElGamal 不一样，先去看 `p` 是不是合数、`g` 的阶是不是很小——那才是另一类打法。

## 七、附件与脚本

现场目录：`D:\XiaoMibook\CTF学习\elgamal_em_g3\`（只读留档，未改动）。

| 文件 | 大小 | 作用 | 实测 |
|---|---|---|---|
| `params.json` | 2,942 B | 题给参数：`p`／`g`／`public_key_h`／`ciphertext.c1`／`ciphertext.c2`，外加 `incident` 与 `note` | — |
| `check.py` | 2,774 B | 参数体检：`p == G14`、`p`／`q` 素性、`p-1` 分解、`ord(g)`、`h` 子群一致性、`BSGS(2^20)` 探针 | 1.41 s，输出见 3.1 |
| `decrypt.py` | 569 B | 把 `x = 139` 写死后只做验证与解密，用来交叉确认结果 | 输出见 3.5 |
| `solve_elgamal.py` | 5,636 B | **完整解法**：内嵌参数（也可读外部 `params.json`）→ 三级 BSGS 阶梯 → `pow` 复核 → 解密并打印 hex 与明文 | 0.14 s，输出见 3.6 |

跑法：

```bash
# 自包含（用脚本内嵌的参数）
python solve_elgamal.py

# 用题给参数文件
python solve_elgamal.py params.json
```

`solve_elgamal.py` 是**从参数出发自己求 `x`** 的，不是把 `139` 写死；`decrypt.py` 才是“已知 `x` 的复核版”。写 WP 或复查时建议两个都跑：一个证明推导链闭合，一个证明结论可独立复现。
