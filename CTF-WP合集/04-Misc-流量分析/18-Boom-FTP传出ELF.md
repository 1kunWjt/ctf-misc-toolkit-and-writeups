# Boom — Writeup

> DASCTF 2025 上半年线上赛（MISC）· 分类：Misc / 流量分析 · 难度：★★★☆☆

| 项目 | 内容 |
|---|---|
| 题目名 | Boom（附件 `boom.pcapng`） |
| 分类 | Misc / 流量分析（FTP 明文 + 主动模式 + ELF 逆向） |
| 附件 | `boom.pcapng`；解出物：`flag`（6120 字节 ELF）、`demo`（6120 字节 ELF）、FTP 目录清单（1777 字节） |
| 一句话 | pcap 里用明文 FTP 凭据 + 主动模式下载了一个 ELF 校验器，真正的活是逆向那个 ELF 的判定逻辑。 |
| 结果 | 未完成（流量侧全部解出、ELF 逻辑完整还原，但 flag 缺一个 24 位口令串，见文末「卡点与正解方向」） |

**最终答案**

```
未取得。

能确定的输出格式（来自 ELF 反汇编，非猜测）：
  flag = "DASCTF{" + f(E[7..22]) + "}" ，f(E[i]) = (E[i] + min(i, 11) - 6) & 0xFF
  E 是程序要求的 24 字节输入：E[0..6] 必须为 "|y~~ww}"，E[23] 必须为 'w'，全程不含 'j' 与 '+'

E[7..22] 这 16 个字节在二进制里不做任何比较，附件里也找不到 —— 不是“算错”，是“缺输入”，本合集不编造。
```

## 一、题目长什么样（先建立直觉）

拿到的是一个 `boom.pcapng`。按流导出的东西很杂：20、21、8000、443、80 端口都有 TCP 会话，还有一堆几字节的“空流”（只有 SYN/ACK，没有载荷）。

只看端口号就能建立直觉：**21 / 20 是 FTP** —— 21 是控制通道（明文，账号密码全在），20 是**主动模式（PORT）下服务器回连的数据通道**，本题的数据就从 20 出来。**8000** 是受害者访问的 `python -m http.server`，只下到目录列表和一两个文件，属旁线；**443 / 80** 是杂项。所以结构是：`明文 FTP → RETR 一个文件 → 数据通道重组 → 拿到的不是文本而是 ELF → 逆它`。

## 二、思路总览

> 结论先行：**这题的“流量”部分在第二步就结束了 —— `RETR flag` 传的是一个 6120 字节的 ELF 校验器，后面全是 Reverse。而且它本身写得“欠约束”，光靠它算不出唯一 flag。**

五步链路：

1. 按四元组拆流（不要按包顺序拼），把 TCP 载荷按 `seq` 落到 `seq - base` 的位置。
2. 认出 FTP，注意 **主动模式**：控制通道先出现 `PORT 192,168,42,150,a,b`，算 `a*256+b` 才是数据端口。
3. 两条数据连接分开：1777 字节那条是 `LIST` 目录清单，**6120 字节那条才是 `flag` 文件**。
4. 6120 字节做 ELF 识别 → 反汇编 `main` → 还原伪 C → 按伪 C 反推“输入 → flag”的变换，判断能否唯一确定 flag（本题答案：不能）。

## 三、逐步复现

### 3.1 第一步：按流拆开，比较每条流的大小

拆流用的是自己写的 pcapng 解析器（现场 `p1.py`～`p8.py`，纯标准库，不依赖 scapy/tshark）。`p8.py` 的两段核心：

```python
# 读 pcapng 的 EPB 块（type=6）：时间戳 + 抓到的字节
if btype == 6:
    iid, th, tl, cap, orig = struct.unpack_from("<IIIII", body, 0)
    pkts.append((th + tl / 1e6, body[20:20 + cap]))

# 按 seq 定位，不用“包出现顺序”
def reassemble(lst):
    lst = sorted(lst, key=lambda x: x[4]); buf, base = bytearray(), None
    for src, sp, dst, dp, seq, data in lst:
        if not data: continue
        if base is None: base = seq
        rel = seq - base
        if rel > len(buf): buf.extend(b'\xff' * (rel - len(buf)))   # 缺口填 0xff，好认
        buf[rel:rel + len(data)] = data
    return bytes(buf)
```

按 `源IP_源端口__to__目的IP_目的端口.bin` 落地后，关键几条（真实长度）：

| 文件 | 长度 | 说明 |
|---|---|---|
| `..._21__to__..._47060.bin` | 538 | FTP 控制通道，`220/331/230/150/226` 全在里面 |
| `..._20__to__..._44595.bin` | 1777 | 数据通道一 = `LIST` 的目录清单（纯文本） |
| `..._20__to__..._49849.bin` | **6120** | 数据通道二 = `RETR flag` 的文件本体 |
| `..._8000__to__..._36580.bin` | 6753 | HTTP 响应（含 6120 字节 ELF 的那个） |

**怎么读**：两条 `:20` 的流长度不同，一定要分清。1777 那条一开就是 `-rw-r--r-- 1 0 0 978 …` 的 `ls -l` 格式，是清单；6120 那条前四字节 `7f 45 4c 46`，是 ELF。

### 3.2 第二步：读 FTP 控制通道，确认主动模式与文件名

控制通道明文可读：

```
USER kali
PASS root
SYST
PORT 192,168,42,150,174,51      -> 174*256 + 51  = 44595   (LIST 的数据口)
LIST
PORT 192,168,42,150,194,185     -> 194*256 + 185 = 49849   (RETR flag 的数据口)
TYPE I
RETR flag
150 Opening BINARY mode data connection for flag (6120 bytes)
226 Transfer complete.
```

两个关键判定：① **这是主动模式（PORT），不是 PASV** —— 数据连接的服务端端口恒为 20，客户端端口由 `PORT` 的 `a*256+b` 决定，所以 `:20` 的两条流就是全部数据；② `150` 那行自报 **6120 bytes**，与 3.1 重组结果**完全一致**，等于免费做了一次长度自校验（没漏包、没拼错）。

`LIST` 清单里还有个关键细节（真实节选）：

```
-rw-r--r--    1 1000     1000         6120 Apr 27 16:18 demo
-rw-r--r--    1 1000     1000         6120 Apr 27 16:18 flag
```

`demo` 与 `flag` **同为 6120 字节、同一分钟编译** —— 这是后面最大的坑（见 3.6 与第五节）。

### 3.3 第三步：6120 字节的 `flag` 是什么

段布局很干净：**5 个 TCP 载荷，seq 连续，无重传无缺口，1448×4 + 328 = 6120**，所以按 seq 拼接是唯一正确结果。落地成 `flag_elf.bin` 后：

```
len = 6120
Usage: %s <input_string>  ·  Error: Input must be exactly %d characters long.
|y~~ww}  ·  Error: Input format incorrect.  ·  DASCTF{  ·  GCC 7.5.0 (Ubuntu 18.04)
```

一眼定性：**flag 校验器/生成器**（导入表只有 `strncmp / strlen / strchr / puts / putchar / printf`，不碰文件、不碰网络）。`.rodata` 仅 0x96 字节，自己 hexdump 出来的排布：

| 虚拟地址 | 内容 |
|---|---|
| 0x9d8 / 0x9f8 | `Usage: %s <input_string>\n` / `Error: Input must be exactly %d characters long.\n` |
| 0xa2a / 0xa38 | `|y~~ww}`（7 字节 + NUL） / `Error: Input format incorrect.` |
| 0xa57 / 0xa5f / 0xa62 | `DASCTF{`（8 字节含 NUL） / `%s` / `%c\n` |

### 3.4 第四步：反汇编 `main`（0x7aa），还原成伪 C

现场有真实的 `flag_disasm.txt`（objdump 产出），`main` 逐条对过：

```c
int main(int argc, char **argv)
{
    if (argc != 2) { printf("Usage: %s <input_string>\n", argv[0]); return 1; }   // 0x7b9
    if (strlen(argv[1]) != 24) {                                                  // 0x7f7: cmp $0x18
        printf("Error: Input must be exactly %d characters long.\n", 24); return 1;
    }
    if (strncmp(argv[1], "|y~~ww}", 7) != 0       // 0x837: strncmp(...,0xa2a,7)
        || argv[1][23] != 'w') {                  // 0x852: cmp $0x77
        puts("Error: Input format incorrect."); return 1;
    }
    if (strchr(argv[1], 'j') || strchr(argv[1], '+')) {                           // 0x87f / 0x89c
        puts("Error: Input format incorrect."); return 1;
    }
    printf("%s", "DASCTF{");                      // 0x8cf: printf(0xa5f, 0xa57)
    for (int i = 7; i <= 22; i++) {               // 0x8db 起：i 从 7 到 0x16
        int t = (i > 11) ? 11 : i;                // 0x8e4: cmpl $0xb
        putchar((char)((t + argv[1][i] - 6) & 0xFF));    // 0x916: sub $0x6
    }
    printf("%c\n", '}');                          // 0x942: printf(0xa62, 0x7d)
    return 0;
}
```

**怎么读**：判定条件只有 4 个 —— 长度 24、前 7 字节 `== "|y~~ww}"`、第 24 字节 `== 'w'`、不含 `j` 与 `+`。输出 = `"DASCTF{"` + 16 个变换字节 + `"}"`，变换是**按位置加常数再减 6**。也就是说：**它根本没有“比较”输入对不对**（没有把输入与任何密文做全串 `strncmp`），只是把你给的 16 个字符移位后拼进 `DASCTF{…}` 打出来。这就是整题的转折点。

### 3.5 第五步：用 Python 复刻变换，验证“欠约束”

翻成 Python（现场 `boom_algo.py` 就是这么写的）：

```python
def f(E):                                   # E 为 24 字节输入
    out = bytearray()
    for i in range(7, 23):
        out.append(((i if i <= 11 else 11) + E[i] - 6) & 0xFF)
    return b"DASCTF{" + bytes(out) + b"}"

print(f(b"|y~~ww}" + b"A"*16 + b"w"))       # 通过校验，也打印出一个“flag”
print(f(b"|y~~ww}" + b"B"*16 + b"w"))       # 同样通过，但输出不同
```

两组不同输入都“合法”，输出却不同 → **flag 不唯一**，光凭这个 ELF 得不到唯一答案。于是自然的下一步：另一个 ELF `demo` 是不是给这个口令用的？

### 3.6 第六步：`demo` ELF 与 0..10000 密钥穷举（失败）

`demo` 是从 **HTTP 8000** 下载的（响应 `Content-Length: 6120`），现场存成 `demo_disasm.txt`。它的字符串是 `Usage: %s <24-byte-string> <0-10000-number>`、`Error: First argument must be exactly 24 characters.`、`Encrypted Output: %s` —— 是**编码器**，不是校验器。反汇编核心循环（`0x7ee`–`0x862`，真实指令）：

```
804: movzbl %al,%eax              ; key & 0xFF          809: xor %eax,%esi     ; c ^ (key & 0xff)
813-826: key - (key/93)*93        ; = key % 93          82a: lea (%rsi,%rax,1),%ecx  ; + (key % 93)
82d-84a: % 94                     ; magic 0xae4c415d    84e: lea 0x21(%rax),%ecx    ; + 33
```

公式即 `enc(c, k) = (((c ^ (k & 0xFF)) + (k % 93)) % 94) + 33`。

**假设**：作者先用 `demo` 把真 flag 编成 24 字节密文 E，再让 `flag` 拿 E 当输入 —— 那就该存在某个 `k ∈ [0,10000]` 使 `enc("DASCTF{", k) == "|y~~ww}"`。穷举结果：**命中 key = `[]`，一个都没有。**

顺手排除掉的朴素猜想：

| 猜想 | 结果 |
|---|---|
| `E[0..6]` 是 `"DASCTF{"` 异或固定 key / 减固定偏移 | 差值 `0x38,0x38,0x2d,0x3d,0x23,0x31,0x06`、`0x38,0x38,0x2b,0x3b,0x23,0x31,0x02` 均无规律 |
| 校验器的移位就是 `demo` 的逆运算 | 随机抽样 200 组 key 验证，`decrypt(encrypt(s)) != s[7:23]`，**不互逆** |

所以两个 ELF 之间**不存在**“加密器 → 校验器”的密钥对应关系，流量侧能榨的东西到此榨干。

### 3.7 旁线：HTTP 8000 的复现（解释 `demo` 从哪来）

`p8.py` 对 8000 端口按 `text/html` 分流打印响应，真实结论：`GET /` → 2490 字节的 `http.server` 目录列表（`/home/kali`，含 `桌面/图片/模板/音乐/视频`、`1111.py`、`222.py`、`demo`、`flag`、`key.zip`、`pwn`）；`GET /%E6%A1%8C%E9%9D%A2/`（`桌面/`）→ 893 字节，`图片/`、`模板/`、`音乐/` → 各 201 字节（404 页）；其中一条响应是 `application/octet-stream`、6120 字节 —— 就是 `demo`。

即受害机（`192.168.42.150`）在 Kali（`192.168.42.129`）上用两种方式各下了一个 6120 字节 ELF：FTP 下 `flag`，HTTP 下 `demo`。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| FTP 主动模式（PORT） | 客户端在控制通道发 `PORT h1..h4,p1,p2`，服务器从 **20** 主动连回 `p1*256+p2` | 两条数据流都在 `:20`，不认 PORT 就找不到 6120 字节那条 | 任何含 FTP 的 pcap（PASV 则端口在服务端） |
| TCP 按 seq 重组 | 用 `seq - base` 决定写入偏移 | 按包顺序拼会把文件拼错，ELF 解析不了 | 所有流量题的“导出文件”步骤 |
| `150 ... (N bytes)` 自校验 | 服务端传输前自报长度 | 重组 6120 == 自报 6120，证明没拼错 | 抓包里各种协议的长度字段 |
| ELF `.rodata` 布局 | 字符串按地址连续排，`lea rip` 注释直接给地址 | 区分 `\|y~~ww}`(0xa2a) 与 `DASCTF{`(0xa57)，避免混淆 | 一切 ELF 逆向 |
| `strncmp/strchr/strlen` 指纹 | 只有这几个导入＝纯字符串判定 | 一秒定性“这是 flag 校验器” | CrackMe、比赛 checker |
| 欠约束（under-constrained） | 判定条件不覆盖所有输入位，导致多解 | 第 8~23 字节完全没被校验，flag 不唯一 | 判断“这题是不是漏了附件” |
| 位置相关 ASCII 移位 | `out = in + min(i,11) - 6` | 校验器的“打印”逻辑本身就是一次轻量编码 | 换表/换位类简单加密 |

## 五、踩坑与陷阱

1. **`demo` 不是 FTP 传的那个文件。** 两者都是 6120 字节、同一个 `Apr 27 16:18`，最容易误判成“同一文件的两个版本”。判定依据必须是**字符串内容**（一个 `Usage: %s <input_string>`，一个 `Encrypted Output: %s`），不是文件大小。
2. **别按包顺序 concat。** 6120 这条恰好 seq 连续，但同目录 1777 字节的 LIST 流和 8000 端口的流都有乱序，按出现顺序拼会得到半截文件。
3. **主动模式别去找 PASV 端口。** 数据连接服务端端口固定 20，容易误判“没有 PASV 就没有数据”。
4. **`|y~~ww}` 不要当成 `DASCTF{` 的异或/移位密文**（异或、减偏移、`demo` 全 key 穷举全试过，都不成立，它就是写死的魔数前缀）；另外 `main` 不是文件开头的第一个函数 —— 0x6a0 是 `_start`，`main` 在 0x7aa，从头往下读会先撞一堆 `deregister_tm_clones`。

## 六、赛场 20 分钟行动清单

1. `0–2 min`：`统计 → 协议分级`。看到 FTP 就去 21，看到 8000 记一笔“旁线”。
2. `2–5 min`：Follow TCP Stream 看控制通道，抄下 `USER/PASS/PORT/RETR`，把 `PORT` 的 `p1*256+p2` 算出来。
3. `5–8 min`：数据连接上 `Follow > TCP Stream > Raw > Save as`，得到 6120 字节，用 `150 ...(6120 bytes)` 对账。
4. `8–10 min`：`file` / `strings`。见 `DASCTF{` + `|y~~ww}` + `Usage:` 就定性校验器；见 `Encrypted Output` 那是另一个程序。
5. `10–18 min`：从 `main` 反汇编，把判定条件列成 4 条，把打印循环翻成伪 C。
6. `18–20 min`：判断“能否唯一确定 flag”。一旦发现中间 16 字节不校验 → **记录已知信息、标记卡点、跳题**；超过 25 分钟还在纠结“`|y~~ww}` 是怎么从 `DASCTF{` 变来的”就是踩进了死路（见下节）。

## 七、附件与脚本

| 路径 | 说明 |
|---|---|
| `boom/192.168.42.129_20__to__192.168.42.150_49849.bin` | FTP `RETR flag` 数据流，6120 字节，内容即 ELF |
| `boom/192.168.42.129_20__to__192.168.42.150_44595.bin` | `LIST` 目录清单，1777 字节纯文本 |
| `boom/flag_elf.bin`、`boom/elfs/*.bin` | 同一 ELF 的另存/候选副本（各 6120 字节，SHA256 `3049E716…D132D65E`） |
| `boom_pcap/ftp_data_retr_flag.bin`、`ftp_data_list.txt` | 最终采用的 ELF 与清单落地版（可读 `demo/flag` 同为 6120） |
| `boom_pcap/p1.py`…`p8.py` | 纯标准库 pcapng 解析脚本，`p8.py` 是最终版（流重组 + HTTP 响应打印） |
| `boom_pcap/flag_disasm.txt`、`demo_disasm.txt`、`http_dns_dump.txt` | 两个 ELF 的 `objdump -d`（`main` 在 0x7aa / 编码循环 0x7ee–0x862）；8000 端口 HTTP 全量 dump |
| `misc_attachment/boom_algo.py` | 复盘脚本：复刻移位变换 + 0..10000 密钥穷举 `enc("DASCTF{") == "|y~~ww}"` |

跑法：`python p8.py`（脚本里的 pcap 路径改成本机 `boom.pcapng`）；`python boom_algo.py` 输出 `命中 key: []`，即两 ELF 无密钥对应关系。

## 卡点与正解方向

**已确认（有据可查）**

1. pcap 主线全解出：明文 FTP、`kali/root`、主动模式两条数据连接、`RETR flag` 6120 字节、长度自校验通过；HTTP 8000 另下到 `demo`。
2. 6120 字节是 ELF（PIE、GCC 7.5.0 / Ubuntu 18.04），`main` 已完整还原成伪 C（见 3.4）；flag 的**生成方式**确定：`"DASCTF{" + 16 字节移位 + "}"`，移位 `+min(i,11)-6`。
3. 校验器**只校验 4 件事**：总长 24、前 7 字节 `|y~~ww}`、第 24 字节 `w`、禁用 `j`/`+`。**第 8~23 字节不参与任何比较。**
4. `demo` 的编码算法确认，且 `k ∈ [0,10000]` 穷举后没有任何 k 能把 `DASCTF{` 编成 `|y~~ww}`。

**卡在哪**：缺那 24 字节口令串 `E`。校验器不校验 `E[7..22]`，这 16 字节是自由变量；`E` 又不在 pcap 的任何一条流里 —— `LIST` 里出现的 `WTF`(30 B)、`1111.py`(978 B)、`222.py`(963 B) 都没走数据通道，拿不到。

**正解方向（按投入产出排序）**

1. **查官方/公开 WP 或向出题人确认**：会话里比对过 DASCTF 2025 上半年的一篇公开题解（bili33.top），其中 MISC 有多题标注“未出”，说明大概率是**附件缺了提示文件**，而不是思路错。
2. **找原始附件里没被传的那几个文件**（`WTF`、`1111.py`、`222.py`、`key.zip`）：`E` 最可能以明文躺在里面 —— 它们在 `LIST` 里看得见，但没走数据通道。
3. **拿到官方 `E` 后一行出 flag**：`E = b"|y~~ww}" + b"????????????????" + b"w"`，然后 `print(b"DASCTF{" + bytes((min(i,11) + E[i] - 6) & 0xFF for i in range(7,23)) + b"}")`。
4. **别再走“两 ELF 联动”的老路**：`demo` 全 key 空间已验证无解；若坚持从 `demo` 入手，需要先证明作者的 `E` 是 `demo(flag, k)` 的输出，而现有证据（前缀对不上、移位不互逆）是反证。
