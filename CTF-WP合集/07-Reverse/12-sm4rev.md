# 第 12 题 · sm4rev — Writeup

> DASCTF 题包 · 分类：Reverse（国密 SM4） · 难度：★★★☆☆

| 项目 | 内容 |
|---|---|
| 题目名 | sm4rev（第 12 题，信创安全方向） |
| 分类 | Reverse（SM4 国密分组密码） |
| 附件 | `sm4rev`（726,941 字节，makeself 自解压脚本，里面裹着一个 1,950,648 字节的静态 ELF） |
| 一句话 | 输入被 PKCS#7 补齐后用 SM4-ECB 加密，与 48 字节常量逐字节比对；密钥就摆在 checker 的 `movabs` 立即数里 |
| 结果 | `DASCTF{SM4_is_secure_but_d0nt_t3ll_any0ne!}` |

**最终答案**

```
DASCTF{SM4_is_secure_but_d0nt_t3ll_any0ne!}
```

## 一、题目长什么样（先建立直觉）

附件名为 `sm4rev`，没有扩展名，726,941 字节。用文本方式打开头部，看到的是 `/bin/sh` 脚本：

```
#!/bin/sh
skip=49
...
```

这是 **makeself** 自解压包：一段 shell 头 + 直接拼在后面的压缩载荷。`file` 会说它是 shell script，`strings` 里能瞥见 `tar`、`gzip` 的字样——但真正的程序藏在后面。

把载荷拆出来，才拿到本体：一个 **x86-64 静态链接、已 strip、非 PIE 的 ELF**，1,950,648 字节，入口 `0x404ae0`，`.text` 有 `0x1760eb` 字节（大部分是静态 glibc）。因此它能在任何 Linux／WSL 里直接跑，而题目名字已经明说了考点：**SM4**（国密分组密码，GB/T 32907-2016）。

## 二、思路总览

1. 认出 makeself 头，按 `skip=49` 的语义算出载荷起点（关键：是"第 49 行的开头"，不是"第 49 行之后"）；
2. 载荷是 gzip（FNAME 写着 `sm4_rev`），解出来就是单个可执行文件，不是 tar；
3. 静态 + strip 的 ELF 不好找 `main`，但**非 PIE**，所以直接搜"谁引用了提示字符串 `please input flag: `"就能落到 `main`；
4. `main` 把输入交给 checker（`0x404cb0`），checker 里用 `movabs` 立刻数压了一个 16 字节密钥和 48 字节目标密文；
5. `.rodata` 紧跟 `wrong!` 后面就是**标准 SM4 S 盒**与写死的 T 表 → 确认是 SM4，不是自造算法；
6. 48 字节密文的最后 5 个字节是 `0x05`，说明尾块用了 **PKCS#7** 补齐，flag 长度 43；
7. 用 SM4 解密再剥补齐，得到 flag；用真程序 `printf` 喂进去，回 `right!` 完成互证。

## 三、逐步复现

### 3.1 拆 makeself 头：`skip=49` 到底指哪一行

脚本头一共 48 行（索引 0~47），载荷从**第 49 行的第一个字节**开始，也就是索引 48 那一行的行首。这正好对上 `tail -n +49` 的语义（1-based 的第 49 行 = 0-based 的第 48 行）。

按"每行长度 + 1（换行）"累加前 48 行即可：

```python
lines = raw.split(b'\n')
off = sum(len(lines[i]) + 1 for i in range(48))
```

实测输出：

```
file size = 726941
line0..2 = b'#!/bin/sh' b'skip=49' b''
payload offset = 888 hex=0x378
payload head 16 = 1f 8b 08 08 eb 48 1f 67 02 03 73 6d 34 5f 72 65
```

`1f 8b 08 08` 是 gzip（CM=8、FLG=0x08 → 带 FNAME），紧接着的 `73 6d 34 5f 72 65 76 00` 就是原始文件名 `sm4_rev`。

> 容易踩的坑：`skip=49` 写成"跳过 49 行"就会多跳一行，落点变成 gzip 数据中间，`gzip.decompress` 直接报错。第一次尝试就是这么失败的。

### 3.2 解出载荷：gzip 里是单个可执行文件

```
decompressed = 1950648 head = 7f 45 4c 46 02 01 01 00 00 ...
ISIZE tail = 1950648
```

`7f 45 4c 46` = `\x7fELF`，并且 gzip 尾部的 ISIZE 与实际解压长度一致（1,950,648）。尝试用 `tarfile` 打开会抛 `TarError`，说明 makeself 走的是"单文件模式"（`gzip -cd > "$xxx"; chmod +x`）——所以**别去找 tar 目录结构**。

### 3.3 认 ELF：静态、strip、非 PIE

```
Type: EXEC (Executable file)        <- 非 PIE，基址固定 0x400000
Entry point address: 0x404ae0
[ 7] .text   PROGBITS 0x401230 0x1760eb  AX
[10] .rodata PROGBITS 0x57a000 0x022dd8  A
```

非 PIE 是这题最大的便利：代码里对常量字符串的引用是**绝对地址**，反查字符串就能立刻锁定函数。

### 3.4 顺着提示字符串找到 `main`

`please input flag: ` 在文件偏移 `0x17a005`，对应 VA `0x57a005`（`.rodata` 从 `0x57a000` 开始）。用 `objdump -d` 全量反汇编后，搜"谁引用 `0x57a005`"：

```
404f46: 48 8d 35 b8 50 17 00   lea 0x1750b8(%rip),%rsi   # 0x57a005
```

`0x404f28` 就是 `main`，结构一目了然：

```
404f46: lea  rsi, "please input flag: "
404f4d: lea  rdi, std::cout
404f54: call 0x4754c0            ; operator<<
404f59: lea  rax,[rbp-0x90]      ; 栈上的 std::string
404f63: lea  rdi, std::cin
404f6a: call 0x40c7c0            ; std::getline(cin, str)
404f79: call 0x401200            ; std::string::size()
404f8e: call 0x404cb0            ; check(str.data(), len)
404f95: je   0x404fc1            ; 假 → 0x57a020 "wrong!"
404f97: lea  rsi, 0x57a019       ; 真 → "right!"
```

顺手把 `.rodata` 的头 0x200 字节打出来，信息量极大：

```
57a000 01000200 00706c65 61736520 696e7075   "please inpu"
57a010 7420666c 61673a20 00726967 68742100   "t flag: \0right!\0"
57a020 77726f6e 67210000                     "wrong!\0"
57a040 d690e9fe cce13db7 16b614c2 28fb2c05   <- SM4 S 盒（256 字节）
57a140 5b5bd58e 424292d0 a7a7ea4d fbfbfd06   <- 写死的 T 表（256×4 字节）
```

`d6 90 e9 fe cc e1 3d b7 ...` 正是国标 SM4 的 S 盒首 8 字节。往后 1024 字节的 `5b 5b d5 8e ...` 是把「S 盒 + 循环左移」合成一张表的 **T 表**写法（很多国密参考实现都这么干）。附带解释了一个现象：在文件里搜 `FK`（`a3b1bac6...`）和 `CK`（`00070e15...`）的原始字节是搜不到的，因为实现走了预计算表。

### 3.5 checker：密钥、目标密文、PKCS#7

`0x404cb0` 开头就是三组 `movabs`，密钥和目标密文全都写在立即数里：

```
404ce3: movabs $0xefcdab8967452301,%rax
404ced: movabs $0x1032547698badcfe,%rdx     →  [rbp-0x70] = 01 23 45 67 89 ab cd ef
                                                            fe dc ba 98 76 54 32 10
404cff..404d4f: 四组 movabs                 →  [rbp-0x50] 起 48 字节目标密文
```

按小端展开，三组 16 字节就是：

```
825dad7df74bde01dc9e6a43066c454f
850d696d4e9184654222d8b032c5ab2d
83d3a869835b203e3abc5e12243735bf
```

接下来是控制流，逻辑等价于：

```c
char* check(const char* s, size_t len) {
    uint8_t key[16]   = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                         0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t target[48] = { ... };          // 上面的 48 字节
    size_t padded = ((len >> 4) + 1) << 4; // 16 的倍数，且总是多留一块
    uint8_t buf[padded];                   // VLA
    memcpy_pkcs7(buf, s, len);             // PKCS#7 补齐（0x404c05）
    sm4_key_schedule(&ctx, key);           // 0x40872d
    for (size_t i = 0; i < padded; i += 16)
        sm4_encrypt(&ctx, buf + i, block); // 0x40506a：单块、无链接
    return bytes_equal(all_blocks, target); // 逐字节比对，计数器连续走完 48 字节
}
```

两个可以直接读出来的特征：

- **每块独立加密**（`0x40506a(ctx, in+i, out)` 之间不共享状态），且比对时用一个连续的字节计数器走完 48 字节 → 就是 **ECB 拼接**，没有 CBC 那种链。
- `len>>4 +1 <<4` 这一串是 `((len/16)+1)*16`，配合尾部补齐 → **PKCS#7**。48 字节对应明文长度在 32~47 之间。

### 3.6 解密：SM4-ECB + 剥 PKCS#7

写一份标准 SM4（`src/zj12/sm4rev_solve.py`，S 盒字节直接抄自 `0x57a040`），先用国标向量自检，再解本题：

```
[i] 国标测试向量 = 681edf34d206965e86b3e94f536e4246  期望 = 681edf34d206965e86b3e94f536e4246  一致 = True
[*] 解密结果 = b'DASCTF{SM4_is_secure_but_d0nt_t3ll_any0ne!}\x05\x05\x05\x05\x05'
[OK] 去掉 PKCS#7 填充 = DASCTF{SM4_is_secure_but_d0nt_t3ll_any0ne!}
[i] 再加密一遍 == 原密文 ? True
```

末块 5 个 `0x05` 正好是 PKCS#7 的填充长度（43 + 5 = 48），与 `len>>4 +1 <<4` 的补齐方式完全吻合；`再加密一遍 == 原密文` 则是密码学意义上的自校验。

### 3.7 动态验证

程序只认 stdin，把 flag 用 `printf` 灌进去即可：

```
$ printf 'DASCTF{SM4_is_secure_but_d0nt_t3ll_any0ne!}\n' | ./sm4rev_bin
please input flag: right!
RC=0

$ printf 'DASCTF{SM4_is_secure_but_d0nt_t3ll_any0n3!}\n' | ./sm4rev_bin
please input flag: wrong!
RC=0
```

把结尾的 `y0ne` 改成 `y0n3` 就掉到 `wrong!`，说明这条 43 字节的明文就是答案。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| makeself 自解压包 | shell 头 + `skip=N` + 紧随其后的压缩载荷 | 用"看起来是脚本"骗过 `file`/`strings` 的第一轮判断 | Linux 商业安装包、`.run` 文件 |
| `tail -n +N` 语义 | N 是 1-based 行号，落点是该行**行首** | 差一行就解不开 gzip | 所有 makeself 拆包 |
| gzip FNAME | `FLG` 的 bit3 置位时，头里带原始文件名（`\0` 结尾） | 直接告诉你载荷原名 `sm4_rev` | 单文件压缩载荷识别 |
| 非 PIE 静态 ELF | 基址固定 `0x400000`，常量引用是绝对地址 | 用 `# 0x57a005` 注释就能反查函数 | 老式 CTF ELF、静态链接目标 |
| SM4 的 T 表 | `T = S 盒 + rotl(2,10,18,24)` 合成 256×4 表 | 文件里搜不到 FK/CK 原始字节 | 国密实现、性能优化版 |
| PKCS#7 补齐 | 补 `n` 个值为 `n` 的字节，长度必为块长整数倍 | 48 = 43 + 5，直接读出明文长度 | AES/SM4 题的通用水印 |
| ECB 与 CBC 的区分 | 看块间是否共享状态/链式变量 | 本题每块独立，比对计数器连续 | 所有分组密码模式识别 |

## 五、踩坑与陷阱

1. **附件不是 ELF 而是 shell 脚本**。`file sm4rev` 报 shell script 时别急着怀疑附件坏了。
2. **`skip=49` 的落点**：写成"跳过 49 行"会落到 gzip 数据中间，直接解压失败；正确是"第 49 行行首"，实测偏移 `0x378`。
3. **gzip 里不是 tar**。`tarfile.open` 一定抛 `TarError`，因为 makeself 走的是单文件模式；硬等 tar 解包会陷在"格式不对"里。
4. **在文件里搜 `FK` / `CK` 会一无所获**。该实现用预计算 T 表 + `movabs` 立即数存密钥，`FK`/`CK` 不作为连续字节存在；改用"S 盒比对"就能确认是标准 SM4。
5. **`wrong!` 与 `please input flag: ` 之间只有 `right!` 三个字的空隙**（`0x57a019`），如果只 grep 到 `wrong!` 会以为没有成功提示。
6. **Windows 上跑不了这个载荷**（静态 x86-64 ELF）。要么 Linux，要么 WSL；`chmod +x` 后直接执行即可，不需要额外依赖。
7. 静态链接 + strip 会让 `objdump -d` 输出 38 万行，别整篇读；用「`objdump -d > dis.txt` + grep 字符串地址」的方式定位函数，效率高一个量级。

## 六、赛场 20 分钟行动清单

1. `head -c 200 sm4rev`，看到 `#!/bin/sh` + `skip=49`，判定 makeself，1 分钟。
2. 按"前 48 行长度 +1"累加算偏移，验证 `1f 8b 08 08`，2 分钟。
3. `gzip.decompress` → `\x7fELF`，落盘 `sm4_rev`，`file` 看是静态 x86-64、非 PIE，2 分钟。
4. `objdump -d` 落盘 + `strings -t x` 找 `please input flag: `，反查引用 → `main`，3 分钟。
5. 进 checker（`0x404cb0`），抄 `movabs` 的 16 字节密钥与 48 字节目标密文，并确认补齐是 PKCS#7、模式是 ECB，4 分钟。
6. `.rodata` 里比对 S 盒首 8 字节，确认标准 SM4（顺带看到 T 表），1 分钟。
7. 写/调 SM4 解密 + 剥 PKCS#7，用国标向量自检，4 分钟。
8. 再加密回验 + 真空跑一次看 `right!`，2 分钟。

> 超过 15 分钟还在啃静态 glibc 的 `.text` 就换策略：这题只需要 `main` + checker 两个函数，其余 99% 是 libc。

## 七、附件与脚本

- 原始附件：`files/tempdir/REVERSE附件/sm4rev`（726,941 字节）；拆包后载荷落在 `solve/payload/sm4_rev`（1,950,648 字节）。
- `src/zj12/sm4rev_solve.py`：纯 Python 的 SM4（密钥扩展 + 加/解密）、国标向量自检、48 字节密文解密、PKCS#7 剥除、再加密回验。直接 `python sm4rev_solve.py`。
- 拆包脚本沿用当时的 `solve/step0_header.py`（打印 makeself 头前 56 行）与 `solve/step1_unpack.py`（算偏移、识别 magic、gzip 解压、判断是不是 tar）。
- 动态验证需要 Linux/WSL：`printf 'DASCTF{...}\n' | ./sm4_rev`，返回 `please input flag: right!`。
