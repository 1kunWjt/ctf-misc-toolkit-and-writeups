# 第 11 题 · Midre — Writeup

> DASCTF 题包 · 分类：Reverse（AES + 反线性反汇编） · 难度：★★★☆☆

| 项目 | 内容 |
|---|---|
| 题目名 | Midre（第 11 题） |
| 分类 | Reverse（序列号校验、AES-128-CBC） |
| 附件 | `attachment.zip`（620,598 字节），解出 `Midre.exe`（59,392 字节）+ `ucrtbased.dll` + `vcruntime140d.dll` |
| 一句话 | 输入先被 `"what's this"` 滚动 XOR，再进 AES-128-CBC 与 32 字节常量比对；靠 `call $+5 / ret` 制造反汇编错位来藏逻辑 |
| 结果 | `726974812f6d9e532f9d838924e6c05f` |

**最终答案**

```
726974812f6d9e532f9d838924e6c05f
```

## 一、题目长什么样（先建立直觉）

附件是个序列号校验程序，双击运行就是一段交互：

```
Please enter the correct serial number:
<输入>
```

对的输入打印 `Congratulations!Welcome to data management system!`，错的打印 `error!` 并以退出码 7 结束。这三个字符串在 `strings` 里一眼就能看到，同时还有两条很像 MD5 的 16 位十六进制串：

```
5855eab53a2275d3
b051a57d6d05b393
what's this
```

以及一条 `Incorrect key length`——它暗示作者自己实现了一份带密钥长度的分组密码。PDB 路径 `F:\01\Daily topic\2023\9\RE0902\re0902.pdb` 说明这是作者 2023 年 9 月的日常练习，Debug 版、`/RTC1` 全开（后面会看到一堆 `szInput` / `szBuffer` / `outlen` 之类的 RTC 变量名）。

二进制是 32 位 MSVC 程序，依赖 `ucrtbased.dll` + `vcruntime140d.dll`（附件里都给了），PDB 里没有符号，所以只能自己找入口。

## 二、思路总览

1. `strings` 拿到四个关键串：提示语、两个 16 位 hex、`what's this`；
2. `.text` 里全是 5 字节 `jmp` 桩（增量链接的产物），所以"找函数"= 找桩的目标地址；
3. 定位 `main`：它引用提示语；找到后发现它先 `scanf("%32s")`，再对 32 字节做滚动 XOR；
4. 真正的判定在一层 `call $+5 / add byte [esp],7 / ret` 之后——这段把 objdump 的线性反汇编**故意打错位**；
5. 判定体里构造一个 20 字节的 AES 上下文：`init(key, 0x80)` → 列数 4、`Nk=4`、`Nr=10`，即 AES-128，密钥是第一条 hex 串；
6. 逐块 `明文 ^= tmp; tmp = AES(block)`，`tmp` 每轮被换成上一块密文——这就是 CBC，第二条 hex 串是 IV；
7. 反推：`serial = AES-128-CBC-dec(key, IV, 目标密文) ^ "what's this"`；
8. 用真 exe 验证：正确 serial 打 `Congratulations!`，改一个字符立刻 `error!`。

## 三、逐步复现

### 3.1 侦察：字符串与导入

```
.textbss  .rdata  .data  .idata  .msvcjmc  .00cfg  .rsrc  .reloc
column   outlen   szInput   szBuffer
error!
Incorrect key length
Please enter the correct serial number:
Congratulations!Welcome to data management system!
5855eab53a2275d3
b051a57d6d05b393
what's this
F:\01\Daily topic\2023\9\RE0902\
\re0902\Debug\re0902.pdb
```

`column` / `outlen` / `szInput` / `szBuffer` 是 `/RTC1` 生成的**局部变量名**（运行时检查用），它们直接把作者函数里的变量名报给了你：一个带 `column` 与 `outlen` 的密码类。

PE 头显示 `HAS_DEBUG / HAS_LINENO / HAS_LOCALS`，但 COFF 符号表是空的——只有 CodeView 里那条 PDB 路径。

### 3.2 先解决"函数在哪儿"

反汇编 `.text` 会看到一片诡异的 5 字节跳转表：

```
411005: e9 b5 7b 00 00   jmp 0x418bbf
41100a: e9 d1 64 00 00   jmp 0x4174e0
...
4113c0: e9 0b 18 00 00   jmp 0x412bd0     <- 判定函数
4113ed: e9 fe 39 00 00   jmp 0x414df0     <- main
```

这不是混淆，是 MSVC **增量链接（/INCREMENTAL）**留下的 `jmp` thunk：每个函数在 `.text` 开头有一个 5 字节桩，桩跳到真实函数。于是"找 main"变成"找桩的目标"，引用 `Please enter...` 的桩就是 `0x4113ed → 0x414df0`。

### 3.3 `main`：读串 → 滚动 XOR → 交给判定

`0x414df0` 处（截取关键几条）：

```
414e18: push 0x41 / push 0 / lea eax,[ebp-0x4c] ; memset(buf2, 0, 0x41)
414e42: push 0x41bdf4                            ; "Please enter the correct serial number:"
414e47: call 0x41111d                           ; printf
414e4f: push 0x27 / push 0 / lea eax,[ebp-0xa4] ; memset(buf, 0, 0x27)
414e62: push 0x27 / push buf / push 0x41bd5c    ; scanf("%32s", buf)
414e70: call 0x41136b
```

`%32s` 写在 `.rdata` 的 `0x41bd5c`，缓冲区 `0x27 = 39` 字节，所以输入上限 32 字符、先被整体清零。

紧随其后是两处**反线性反汇编**的经典手法：

```
414e78: e8 00 00 00 00   call 0x414e7d      ; 下一跳地址入栈
414e7d: 80 04 24 07      add  byte [esp],7  ; 返回地址 +7
414e81: c3               ret                ; → 0x414e84
```

`0x414e84` 落在 objdump 认为的 `83 c4 eb` 指令中间，于是 objdump 从那一点开始全部错位（后面会看到 `ff 50 e8`、`f7 79 04` 这种毫无意义的解码）。同一 pattern 在 `0x414ee1` 又用了一次，跳向 `0x414eed`。

把两段错位区按真实起点手工还原，就得到核心逻辑：

```c
for (int i = 0; i < 0x20; i++)
    buf[i] ^= "what's this"[i % 11];   // 11 字节表在 0x41e048
if (check(buf))                            // 0x41135c -> 0x414bf0
    printf("Congratulations!Welcome to data management system!");
else
    printf("error!");
```

`0x414eac` 处是 `movsx ecx, byte [ebp+eax-0xa4]`，`0x414ec2` 处是 `div 0xb`（`esi = 0xb`）取余——正好对应 11 字节的滚动密钥；循环上界 `cmp [ebp-0xb0], 0x20` 是 32。

### 3.4 判定体：一个 20 字节的 AES 上下文

`0x414bf0`：

```c
char obj[20];                       // memset(obj, 0, 0x14)
aes_init(&obj, "5855eab53a2275d3" @0x41e000, 0x80);   // 密钥 16 字节，128 位
int outlen = 0;
char* out = aes_cbc(&obj, buf, 32,
                    "b051a57d6d05b393" @0x41e024, &outlen);   // 0x412bd0
if (memcmp(out, 0x41e06c, 0x20) == 0) return 1;
```

- `0x414af0` 是构造函数，唯一动作是 `memset(this, 0, 0x14)`——对象 **20 字节**：`[0]=column`、`[4]=Nk`、`[8]=标志`、`[0xc]=Nr`、`[0x10]=密钥指针`。
- `0x411a50` 是 `init(keyptr, keybits)`：存密钥指针、`column = 4`、按 `0x80/0xc0/0x100` 分别设 `(Nk,Nr) = (4,10)/(6,12)/(8,14)`，其它长度走 `printf("Incorrect key length")`（`0x41bdcc`）。这里传的是 `0x80`，所以是 **AES-128**。
- 密钥指针是 `0x41e000`，即 `"5855eab53a2275d3"`——第一条 16 位 hex 串其实是**16 字节 ASCII 密钥**，不是 MD5 的一半。

### 3.5 轮函数是标准 AES（逐个确认过）

| 步骤 | 地址 | 复核结论 |
|---|---|---|
| S 盒查表 | `0x4144e0` | `mov 0x41bb30(%eax),%al` 取 256 字节表，正是标准 AES S 盒 |
| SubBytes | `0x414540` | 对 4×4 状态逐元素查表 |
| ShiftRows | `0x414450` → `0x414340` | 第 i 行做 `row[k] = row[(k+i)%4]`，左移 i 位 |
| MixColumns | `0x413d90`（轮内第三次调用） | 按列下放给 `0x413ef0`；底层 `0x414910` 就是标准 `xtime`（`imul 0x1b` 收溢出） |
| AddRoundKey | `0x411b80` | `state[i][j] ^= roundkey[i+4j]`，列主序 |
| 密钥扩展 | `0x413b70` | `rk[i] = rk[i-Nk] ^ T'(rk[i-1])`，Rcon 表在 `0x41bd30`：`01 02 04 08 10 20 40 80 1b 36` |

轮序是 `SubBytes → ShiftRows → MixColumns → AddRoundKey`，末轮去掉 MixColumns——和 FIPS-197 完全一致。也就是说**密码学部分是标准 AES-128**，不需要自己发明实现；最硬的证据是最后一步正向重算能把 32 字节目标密文一字不差地复现出来。

### 3.6 关键一跃：`tmp` 不是密钥，是上一块密文

`0x412bd0` 的逐块循环初看很怪：

```c
memcpy(tmp, key, 16);                     // 一次
for (i = 0; i < outlen / 16; i++) {
    block_xor(&buf[i*16], tmp);           // 0x4146b0：flat XOR 16 字节
    res = aes_block(&obj, &buf[i*16], rk);// 0x4128d0：标准 AES 加密
    memcpy(tmp, res, 16);                 // ← 看起来"多余"的一句
    memcpy(&out[i*16], res, 16);
}
```

如果只看前一轮，`tmp` 是密钥（像是"白化"）；但 `memcpy(tmp, res, 16)` 把 `tmp` 换成了刚算出的密文——下一块的输入就被"上一块密文"XOR。这就是 **CBC**，`IV = 0x41e024` 处的 `"b051a57d6d05b393"`。那条"多余"的 memcpy 正是链式模式本身，删掉它整题就解不出来。

另外 `0x414750` 是补齐函数：长度不足 16 的倍数时补 0（不是 PKCS#7），本题 32 字节正好整除，所以补齐全过程是空操作。

于是完整链路：

```
serial(≤32B) ──XOR "what's this"(i%11)──▶ P ──AES-128-CBC(key, IV)──▶ C
判定：C == 0x41e06c 起的 32 字节
```

### 3.7 反推与验证

`.data` 里三个常量摆在一起，非常清楚：

```
41e000  5855eab53a2275d3 00000000 ...   <- AES 密钥（ASCII，16 字节）
41e024  00..00 b051a57d 6d05b393 ...    <- CBC IV（ASCII，16 字节）
41e048  77686174 27732074 686973      <- "what's this"，11 字节滚动 XOR
41e06c  52 06 c4 9d 28 71 26 04 ba 98 4d 20 03 81 39 39
        8c 6e 14 8c 7e bf 44 5a 67 f5 0a 7f 61 7f ce 72   <- 目标密文 32 字节
```

脚本（`src/zj11/midre_solve.py`，自带 FIPS-197 C.1 自检）：

```
[i] FIPS-197 C.1 加密自检 = True / 解密自检 = True
[*] CBC 解密结果 = 405a574d104718455a0f45135104411441464d0c51404f515340424543445d0f
[OK] serial = 726974812f6d9e532f9d838924e6c05f
[i] 正向重算 == 目标密文 ? True
```

用真 exe 验证（把 serial 从 stdin 喂进去）：

```
SERIAL=726974812f6d9e532f9d838924e6c05f exit=0
OUT=Please enter the correct serial number:
Congratulations!Welcome to data management system!

SERIAL=726974812f6d9e532f9d838924e6c05e exit=7
OUT=Please enter the correct serial number:
error!
```

只改最后一个字符就掉进 `error!` 分支，说明这 32 个十六进制字符就是答案。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| 增量链接 jmp 桩 | 每个函数在 `.text` 开头留 5 字节 `jmp` 到真实体 | 让"按函数地址找逻辑"多绕一步 | 所有 MSVC `/INCREMENTAL` 的老程序 |
| `call $+5 / add [esp],n / ret` | 用返回地址当跳转目标，落点故意在别的指令中间 | 让线性扫的反汇编器从此错位 | 反反汇编、壳、恶意样本里极常见 |
| `/RTC1` 变量名字符串 | 调试运行库把局部变量名写进 `.text` | 直接泄露 `column/outlen/szInput/szBuffer` | MSVC Debug 版样本 |
| AES-128 参数表 | `(column, Nk, Nr) = (4,4,10)`，按 keybits 分支 | `init(key, 0x80)` 一眼定分组密码类型 | 任何"自实现 AES"的题目 |
| CBC 的链式 memcpy | 每轮把 `tmp` 更新为上一块密文 | 伪装成"预白化"，实为 IV 链 | 题里最常见的"看起来多余的一行" |
| 常量放 `.data` 相邻 | key / IV / XOR 表 / 期望密文排成一列 | 拿到一个就能顺着读完全部参数 | 逆向题的标准数据布局 |

## 五、踩坑与陷阱

1. **两条 16 位 hex 串不是 MD5 片段**。第一反应会去算 MD5 碰撞或查彩虹表，其实它们是 AES 密钥与 CBC IV 的 ASCII 形式。
2. **`.text` 满是 `jmp` 桩，别当成花指令**。它是增量链接产物；把桩的目标当函数入口即可。
3. **objdump 出来的 `mov DWORD PTR [ebp-0xd4],0x41bdcc` 是真代码里的假引用**。`0x411b07` 那条只在 `keybits` 不等于 128/192/256 时才走，别顺着它去追 `Incorrect key length`，那不是本题路径。
4. **`0x414e78`、`0x414ee1` 两处 `call/ret` 之后必须手工重定起点**（`0x414e84`、`0x414eed`），否则后面整段解码全是垃圾，会误判成"数据区"。
5. **`0x412bd0` 里那句"多余的 memcpy"不能忽略**。它就是 CBC 链；漏掉它会得出"白化 + ECB"的错误模型，解出来是非打印字节。
6. **补齐是补 0 而非 PKCS#7**（`0x414750`），本题 32 字节整除所以无感，但如果输入长度不是 16 的倍数，两种补齐方式会给出不同明文。
7. 反推时先用 FIPS-197 官方向量自检 AES 实现，再解本题数据；否则"实现错"和"模型错"会混在一起排查。

## 六、赛场 20 分钟行动清单

1. `strings` 一把梭：提示语 + 两条 hex + `what's this` + `Incorrect key length`，2 分钟。
2. 认出 `.text` 的 `jmp` 桩，建"桩 → 真实函数"映射，2 分钟。
3. 由提示语找 `main`，读 `scanf("%32s")`、`memset` 与 32 次滚动 XOR，3 分钟。
4. 认出 `call $+5 / add [esp],7 / ret`，手工校正两处错位，3 分钟。
5. 进判定体，抓三件事：`init(key,0x80)`（→AES-128）、每轮 `XOR → AES → 覆盖 tmp`（→CBC）、`memcmp` 目标地址，4 分钟。
6. 抄 `.data` 三组常量（key / IV / 32 字节密文），2 分钟。
7. 写（或调库）AES-128-CBC 解密 + 滚动 XOR，FIPS 向量自检，3 分钟。
8. 把 serial 喂给真 exe，看 `Congratulations!` 收工，1 分钟。

> 超过 20 分钟还在追 `Incorrect key length` 那条分支就跳出来——它是 `init` 的错误出口，和本题无关。

## 七、附件与脚本

- 原始附件：`files/tempdir/REVERSE附件/attachment.zip` → `attachment_unzip/Midre.exe`（59,392 字节）+ `ucrtbased.dll` + `vcruntime140d.dll`（缺 DLL 就跑不起来，Debug 版必须带）。
- `src/zj11/midre_solve.py`：纯 Python 的 AES-128（加/解密 + 密钥扩展）、FIPS-197 C.1 自检、CBC 反推、正向回验。直接 `python midre_solve.py`，输出 `serial = 726974812f6d9e532f9d838924e6c05f` 与 `正向重算 == 目标密文 ? True`。
- 当年会话里还留着 `work/midre.asm`（objdump 全量反汇编）与 `work/strings.txt`，复现时可直接拿来对照 thunk 表。
- 验证命令（PowerShell）：把 serial 写进子进程 stdin，读 stdout 看是否出现 `Congratulations!`。
