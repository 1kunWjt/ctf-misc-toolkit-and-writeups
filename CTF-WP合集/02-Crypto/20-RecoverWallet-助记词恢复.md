# RecoverWallet（BIP-39 缺词恢复）— Writeup

> 2025 第八届浙江省大学生网络与信息安全竞赛·预赛 · 分类：Crypto（区块链/钱包）· 难度：★★★☆☆

| 项目 | 内容 |
|---|---|
| 题目名 | `RecoverWallet` |
| 分类 | Crypto / Misc（BIP-39 助记词 + BIP-32 派生 + keccak 地址） |
| 附件 | `challenge.zip`（257 B，里面只有一个 `tempdir/MISC附件/task.txt`，146 B）；配套 `english.txt`（BIP-39 英文词表，13116 B / 2048 词，非题目附件，解题时补的） |
| 一句话 | 12 词缺 1 词只丢了 11 bit，先用 BIP-39 校验和把 2048 个候选压到 131 个，再用派生地址尾号唯一定位 |
| 结果 | solved：缺失词 `gallery`，地址 `0x7e93…0f80` 与题面打码的尾号对上；flag 形如 `DASCTF{地址}`，本机未上平台提交 |

**最终答案**

```
缺失词   gallery（第 5 个词，词表下标 760）
助记词   ankle assume estate permit gallery eye fancy spring demand dial awkward hole
地址     0x7e93e8eeeee122abf300904ebc446d31d8700f80
EIP-55   0x7E93E8Eeeee122aBF300904eBC446D31D8700f80
私钥     0x3fe01d39dc9bcc2b821e76e4fd4f678f273ac16d70b578addba43dce78376393
```

> 附件里**没有** flag 字符串，题面只给了「缺词助记词 + 打码地址」。2025 年浙江省赛预赛的 flag 统一是 `DASCTF{...}`，本题题面就是用 `DASCTF{}` 包住账户地址，所以 `DASCTF{0x7e93e8eeeee122abf300904ebc446d31d8700f80}` 是**按题面形态推出的提交内容，不是平台回显**；本机没有提交过，不把它当成已验证的 flag。

## 一、题目长什么样（先建立直觉）

附件只有 257 字节，`zipfile` 一读就到底：

```python
>>> z = zipfile.ZipFile("challenge.zip")
>>> z.namelist()
['tempdir/MISC附件/task.txt']          # 只有一个文件，146 字节
>>> print(z.read('tempdir/MISC附件/task.txt').decode())
Mnemonic: ankle assume estate permit (???) eye fancy spring demand dial awkward hole
Ethereum Address: 0x**********************************700f80
```

两行信息：

1. 12 个单词，第 5 个位置是 `(???)`——这就是要恢复的东西，占位符在列表下标 4；
2. 地址是 42 个字符（`0x` + 40 个十六进制），其中 34 位被打成 `*`，只留了尾号 `700f80` 当校验用。

所以这不是「猜 12 个单词」的题，而是「12 个词里只有 1 个不知道」。BIP-39 的 12 词助记词 = 128 bit 熵 + 4 bit 校验和，一个词占 11 bit，因此未知空间只有 `2^11 = 2048`（正好是词表大小）。**完全枚举得完**，难点在「怎么快速筛」。

## 二、思路总览

三步漏斗，越往后越贵，所以顺序不能反：

```text
2048 个候选词
   │  ① BIP-39 校验和（只要 SHA-256 前 4 bit，最便宜）
   ▼
131 个合法助记词（实测值；理论期望 2048/16 = 128）
   │  ② PBKDF2-HMAC-SHA512 2048 轮 → BIP-32 派生 m/44'/60'/0'/0/0 → secp256k1 公钥 → keccak256 取后 20 字节
   ▼
1 个尾号 700f80 的地址 → 缺失词 gallery
```

关键在于**先用校验和筛，再做椭圆曲线**：Keccak 和 secp256k1 是纯 Python 里最慢的两步，把 2048 次压到 131 次，整体开销就只剩那 131 次派生。

## 三、逐步复现

### 3.1 第一步：先把「未知量」算清楚

做什么：确认缺词数量、缺的位置、校验信息的强度。

为什么：如果缺 2 个词就是 2048² ≈ 419 万种组合，虽然还能跑，但要重新设计筛法；缺 1 个词才是「枚举 + 校验」的甜点区。

结论：缺第 5 词（下标 4），地址尾号 6 位十六进制 = 24 bit 的校验强度。131 个候选里期望命中 `131 / 2^24 ≪ 1`，所以只要算法对，**唯一匹配**几乎是必然的——这也反过来成了「我实现对了没有」的自检：如果命中 0 个或 2 个以上，说明派生链路写错了。

### 3.2 第二步：没有库，就自己实现四件套

做什么：用纯标准库实现 Keccak-256、secp256k1、BIP-32、BIP-39。

为什么：当时环境里 `pip install eth-account mnemonic pycryptodome` 装不上（沙箱不让写临时目录），只能自己实现。好在四件套都不长：

```python
# BIP-39：seed = PBKDF2-HMAC-SHA512(助记词, "mnemonic"+passphrase, 2048 轮, 64 字节)
def mnemonic_to_seed(mnemonic, passphrase=""):
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"),
                               ("mnemonic" + passphrase).encode("utf-8"), 2048, 64)

# BIP-39：校验和 = SHA-256(熵) 的前 (词数*11 - 熵位数) bit
def bip39_checksum_ok(words, wl_index):
    bits = "".join(format(wl_index[w], "011b") for w in words)
    ent_len = len(words) * 11 * 32 // 33
    ent = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    cs = format(hashlib.sha256(ent).digest()[0], "08b")[: len(words) * 11 - ent_len]
    return bits[ent_len:] == cs

# BIP-32：硬化用 0x00||k||i，非硬化用压缩公钥 02/03||X||i
def ckd_priv(k, c, i):
    if i >= 0x80000000:
        data = b"\x00" + k.to_bytes(32, "big") + i.to_bytes(4, "big")
    else:
        x, y = _mul(k)
        data = (b"\x03" if (y & 1) else b"\x02") + x.to_bytes(32, "big") + i.to_bytes(4, "big")
    i2 = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(i2[:32], "big") + k) % N, i2[32:]
```

怎么读：注意 `bip39_checksum_ok` 里 `ent_len = 词数*11*32//33`——12 词时是 128 bit 熵、4 bit 校验，正好对上「2048 里剩 ~128 个」的直觉。

地址那一步是：`keccak256(X||Y)[-20:]`。**公钥必须用未压缩的 64 字节**（`X||Y`，去掉 0x04 前缀），而 BIP-32 非硬化派生里**必须用压缩公钥**（`02/03||X`）——这两个「压缩/不压缩」不是一回事，下面第 3.3 节会看到它有多致命。

### 3.3 第三步：先对齐测试向量，再谈爆破

做什么：拿两个「业界公认」的向量卡自己的实现。

为什么：纯手写的 Keccak 和 secp256k1 一旦错一位，输出会是一串看起来同样「像地址」的垃圾，你不会察觉。

```text
BIP-32 官方向量：种子 000102…0f → m/0'/1 的私钥/链码必须与 BIP-32 文档一致
Hardhat 默认助记词：test test test test test test test test test test test junk
  → m/44'/60'/0'/0/0
  → 地址 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
  → 私钥 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

第一次跑，第一个向量过了、Hardhat 那个死活对不上（算出来是另一个地址）。排查顺序：PBKDF2 没问题（TREZOR 向量过）→ 主密钥没问题（BIP-32 向量过）→ 问题只能在**非硬化派生**。真凶就是上面那句：`ckd_priv` 的非硬化分支里我一开始把公钥序列化成了未压缩的 65 字节，改成 `02/03||X` 的 33 字节后一次通过。

这一步花的时间比写爆破脚本还长，但它换来了后面「131 个候选只命中 1 个」的确定性——否则根本分不清是「题错了」还是「我错了」。

### 3.4 第四步：跑爆破

```bash
python solve_recover.py       # 词表已缓存为 english.txt，不会联网
```

本机复跑实测耗时 **17.75 秒**（纯 Python，131 次派生），输出逐字如下：

```text
[*] known words: 11  unknown position: 4
[+] MATCH: ankle assume estate permit gallery eye fancy spring demand dial awkward hole
    address : 0x7e93e8eeeee122abf300904ebc446d31d8700f80
    privkey : 0x3fe01d39dc9bcc2b821e76e4fd4f678f273ac16d70b578addba43dce78376393
[*] checksum-valid candidates: 131
```

怎么读这个输出：

- `checksum-valid candidates: 131`——2048 个词里只有 131 个能让 12 词助记词通过 BIP-39 校验和，和 `2048/16` 的量级吻合，说明校验和实现是对的；
- `MATCH` 只有一行——131 个候选里只有一个派生出的地址以 `700f80` 结尾，与题面打码部分完全对齐，缺失词锁定为 `gallery`；
- 脚本还会顺手打印私钥，方便验收时用别的工具交叉验证。

### 3.5 第五步：验收

三条互相独立的证据：

1. **尾号**：`0x7e93e8eeeee122abf300904ebc446d31d8700f80` 的后 6 位是 `700f80`，和题面的 `0x***…700f80` 对上。
2. **EIP-55 校验格式**：以太坊地址的混合大小写是 `keccak256(小写地址)` 逐位决定的，算一遍能再验一次 keccak 实现：

   ```text
   EIP-55: 0x7E93E8Eeeee122aBF300904eBC446D31D8700f80
   ```

3. **词表自检**：`english.txt` 正好 2048 词（`abandon` … `zoo`），`gallery` 在下标 760 —— 三个数都对得上，说明词表和索引没串位。

另外，`131` 这个数字本身就是第四条证据：它是「11 词固定 + 4 bit 校验」的必然结果，题目作者也控制不了它。

### 3.6 关于 flag 形态

题面把地址打码到只剩 6 位，说明**地址就是答案**（打码是为了防止你直接抄）。2025 年浙江省赛预赛的 flag 统一为 `DASCTF{...}`，本题即「`DASCTF{}` 包裹账户地址」，所以提交内容应当是：

```text
DASCTF{0x7e93e8eeeee122abf300904ebc446d31d8700f80}
```

这里如实说明：附件里没有任何 `DASCTF{...}` 字符串，这一行是按题面形态推出来的，本机**没有**上平台提交验证。真要提交时，地址用全小写（题面打码段没有大小写信息，比较时也统一按 `lower()` 处理）。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| BIP-39 | 用 2048 词表把熵编码成助记词，末尾附 SHA-256 校验和 | 缺 1 词 = 11 bit 未知，校验和再砍 4 bit | 所有助记词/钱包恢复题 |
| PBKDF2-HMAC-SHA512 | 助记词 → 64 字节种子，salt 是 `"mnemonic"+passphrase`，2048 轮 | 钱包派生的入口，写错就全盘皆错 | 任何 BIP-39 相关题 |
| BIP-32 | 从种子派生私钥树；硬化 `i+0x80000000`，非硬化用压缩公钥 | `m/44'/60'/0'/0/0` 是 MetaMask 默认路径 | HD 钱包、地址推导 |
| Keccak-256 ≠ SHA3-256 | 两者填充字节不同（`0x01` vs `0x06`） | 以太坊地址用的是 Keccak-256 | 所有 EVM 相关题 |
| 以太坊地址 | `keccak256(uncompressed_pubkey)[-20:]` | 从私钥走到地址的最后一步 | 钱包、签名验签 |
| 尾号校验 | 打码地址留 6 位十六进制 = 24 bit | 用来在多个候选里唯一确定 | 一切「恢复一半」的题 |

## 五、踩坑与陷阱

- **BIP-32 非硬化派生要用压缩公钥**：`02/03 || X`（33 字节），不是未压缩的 `04 || X || Y`。这是本题唯一真正卡住的 bug，用 Hardhat 默认助记词才照出来。
- **Keccak 不是 SHA3**：`hashlib.sha3_256` 算出来的东西和以太坊地址毫无关系；自己实现时填充是 `0x01`，末尾再异或 `0x80`。
- **地址比较统一小写**：题面打码没有大小写信息，`endsWith` 前先 `lower()`，否则大小写会骗你一次。
- **词表必须用 BIP-39 官方 2048 词**：换一份「常用英文词表」会让校验和全部失效。
- **别把真助记词往在线网站贴**：这题是练习无所谓，习惯要养好——本地脚本跑一遍不到 20 秒，没必要上云。
- **`pip` 装不上不是死路**：`mnemonic` + `eth-account` 一条命令就够；装不了第三方库时，纯标准库也就 230 行（见第七节）。

## 六、赛场 20 分钟行动清单

1. 解压看附件：`task.txt` 里是助记词模板 + 打码地址，先数「缺几个词、留了几位」。
2. 缺 1 词就别犹豫，直接枚举 2048；缺 2 词先算一下组合数，再决定要不要上 GPU/多进程。
3. 有网有库：`pip install eth-account mnemonic`，`Account.from_mnemonic` 十行搞定（记得先用 `Mnemonic("english").check` 过校验和）。
4. 有 Node 没 Python 库：`npm i ethers`，`Mnemonic.fromPhrase` 自己会校验和，`HDNodeWallet.fromPhrase` 默认就是 `m/44'/60'/0'/0/0`（`solve_node.js` 就是这条路）。
5. 什么都没有：抄第七节的纯标准库脚本，先跑 BIP-32 官方向量确认实现，再爆破。
6. 命中后用两条独立证据验收：地址尾号 + EIP-55 大小写。

> 15 分钟还没跑出唯一匹配，先怀疑「派生路径」和「压缩/未压缩公钥」，别怀疑题目。

## 七、附件与脚本

| 文件 | 说明 |
|---|---|
| `RecoverWallet/challenge.zip` | 原始附件（257 B），唯一内容 `tempdir/MISC附件/task.txt` |
| `RecoverWallet/english.txt` | BIP-39 英文词表，2048 词 / 13116 B，`solve_recover.py` 的缓存 |
| `RecoverWallet/solve_recover.py` | **纯标准库**解法：Keccak-256 + secp256k1 + BIP-32 + BIP-39，改 `WORDS_KNOWN` 即可复用到同类题 |
| `RecoverWallet/solve_node.js` | ethers.js 版（自带英文词表，无需下载），`node solve_node.js "助记词模板" 700f80` |

`solve_recover.py` 的关键开关都在文件头几行：

```python
WORDS_KNOWN = "ankle assume estate permit (???) eye fancy spring demand dial awkward hole".split()
UNKNOWN_POS = WORDS_KNOWN.index("(???)")     # 自动定位占位符
ADDR_SUFFIX = "700f80"                       # 地址尾号，改这里就能打别的题
```

脚本默认只走 `m/44'/60'/0'/0/0`；如果主路径 0 命中，它会自动再试 `/0`、`/0/1` 两个变体路径，把「路径猜错」这种低级失误挡掉。
