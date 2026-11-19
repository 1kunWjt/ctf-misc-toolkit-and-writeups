# pcap4 · DNS 隧道（dnslog 外带） — Writeup

> 平台：本地靶场（dns.pcapng） · 分类：Misc / 流量分析 · 难度：★★☆☆☆

| 项目 | 内容 |
|---|---|
| 题目名 | pcap4（`dns.pcapng`） |
| 分类 | Misc / 流量分析（DNS 隧道 / DNSLog 外带） |
| 附件 | `dns.pcapng`，21,920 B，178 帧，64 个 DNS 包 |
| 一句话 | flag 被 base64 切段塞进子域名，靠 DNS 查询一段段外带；解码必须**先拼接再解**，逐段解一定错 |
| 结果 | `flag{e662ac154ca376e1c001ee8bbe81318b}` |

**最终答案**

```
flag{e662ac154ca376e1c001ee8bbe81318b}
```

## 一、题目长什么样（先建立直觉）

21,920 字节、178 帧的小包，协议构成很单调：ARP 82 帧、IPv4 88 帧（其中 UDP 82、IGMP 6）、IPv6 8 帧，**一个 TCP 包都没有**。端口统计只有一组有意义的：`53` 占 64 个包。

两端是 `192.168.181.128`（受害/外带主机）与 `192.168.181.2:53`（本地 DNS 服务器，实际是转发器）。域名统一是 `i6ov08.dnslog.cn`——`dnslog.cn` 是公开的 DNSLog 平台，这个后缀一出现，基本就等于写出答案：**有人在用 DNS 查询把数据带出去**。

所以这题不考协议细节，考的是"**看到 dnslog 域名之后，怎么把散落在子域名里的 base64 段按正确顺序拼回来**"。

## 二、思路总览

链路四步：

1. 只留 `dns.flags.response == 0`（查询），把 32 条查询按时间排成一条链；
2. 去掉固定后缀 `.i6ov08.dnslog.cn`，剩下的就是"标签"，逐个看像不像 base64；
3. 把标签**去重、去噪音、按时间顺序拼接成一个完整 base64 串**；
4. 一次 base64 解码，得到 `flag{...}` 加一个换行。

中间有两个坑必须先想明白：`root` / `Z` 这类标签是平台自检，不是数据；`ZmxhZ3` 是 `ZmxhZ3tlNj` 的重复前缀，混进去会把整串长度搞成 59（不是 4 的倍数），直接解崩。

## 三、逐步复现

### 3.1 第一步：30 秒判断这是不是 DNS 隧道

三个判据，命中两个就基本定性：

- 域名后缀是公开 DNSLog 平台（`dnslog.cn` / `ceye.io` / `burpcollaborator.net`）；
- 子域名是 base64 字符集（`[A-Za-z0-9+/]`）且长度固定；
- 大量短查询、无对应业务、响应体是空或 `127.0.0.1`。

本包三条全中：后缀 `dnslog.cn`、标签形如 `ZmxhZ3tlNj`、应答是 `127.0.0.1`。

### 3.2 第二步：不装 pyshark 也能解

一开始照笔记用 `pyshark`，直接报：

```
ModuleNotFoundError: No module named 'pyshark'
```

原因很简单：pyshark 只是 tshark 的 Python 包装，tshark 不在 PATH 里就白搭。两条路——装 Wireshark 用 tshark 过滤，或者干脆自己解 pcapng。

tshark 一行就能出全部查询名：

```bash
tshark -r dns.pcapng -Y "dns.flags.response == 0" -T fields -e frame.number -e dns.qry.name
```

零依赖方案是手写解析（现场 `dns_parse.py` / `dns_tunnel.py`）：先按 pcapng 的 Enhanced Packet Block（块类型 `0x00000006`）取出帧，再解 IPv4 + UDP，最后按 DNS 报文头（12 字节）+ 问题段（label 序列 + Type/Class）读名字。本包实测输出：

```
DNS packets: 64
query types: {'A': 16, 'AAAA': 16}
unique query names: 10
answer records: A 127.0.0.1 x11
```

`A` 与 `AAAA` 各 16 条，说明每个标签都被查了两次（一次 A、一次 AAAA），**统计时必须按名字去重**，否则每个片段都会重复计入。

### 3.3 第三步：把查询名排成时间链

按帧号与相对时间列出全部查询（`dns_tunnel.py` 的真实输出，节选）：

```
#18   19817.917  i6ov08.dnslog.cn
#27   43264.729  root.i6ov08.dnslog.cn
#69   87362.912  Z.i6ov08.dnslog.cn
#101 207652.356  ZmxhZ3tlNj.i6ov08.dnslog.cn
#107 213404.736  ZmxhZ3.i6ov08.dnslog.cn
#115 216598.573  ZmxhZ3.i6ov08.dnslog.cn
#119 235862.045  ZmxhZ3tlNj.i6ov08.dnslog.cn
#127 246520.508  YyYWMxNTRj.i6ov08.dnslog.cn
#135 246715.081  YyYWMxNTRj.i6ov08.dnslog.cn.localdomain
#141 256353.432  YTM3NmUxYz.i6ov08.dnslog.cn
#145 268329.308  AwMWVlOGJi.i6ov08.dnslog.cn
#149 282367.560  ZTgxMzE4Yn0K.i6ov08.dnslog.cn
#153 285431.073  ZTgxMzE4Yn0K.i6ov08.dnslog.cn
#159 299628.102  root.i6ov08.dnslog.cn
```

读这张表能读出四件事：

1. `i6ov08.dnslog.cn`、`root`、`Z` 出现在开头和结尾，是把平台"探活"和"起止标记"当哨兵用，不是载荷；
2. 真正的载荷标签只有 5 个：`ZmxhZ3tlNj`、`YyYWMxNTRj`、`YTM3NmUxYz`、`AwMWVlOGJi`、`ZTgxMzE4Yn0K`；
3. `#107/#115` 的 `ZmxhZ3` 是 `ZmxhZ3tlNj` 的**截断重复**（只发了前 7 个字符），属于噪音；
4. `#135/#136` 那条被系统自动补了 `.localdomain` 后缀（DNS 搜索域的副作用），去掉后缀后与 `YyYWMxNTRj` 是同一个标签。

### 3.4 第四步：拼接再解码（这里是全题分水岭）

先做"逐段解码"，看看会发生什么：

```python
>>> base64.b64decode('ZmxhZ3tlNj' + '==')
b'flag{e6'
>>> base64.b64decode('YyYWMxNTRj' + '==')
b'c&\x163\x13SF'
>>> base64.b64decode('YTM3NmUxYz' + '==')
b'a376e1c'
>>> base64.b64decode('AwMWVlOGJi' + '==')
b'\x03\x03\x16VS\x86&'
>>> base64.b64decode('ZTgxMzE4Yn0K')
b'e81318b}\n'
```

第 1、3、5 段"看起来能解"，第 2、4 段直接是乱码。**这不是解错了，而是段边界没对齐**：base64 是 3 字节一组编码成 4 字符，段长 10 字符（不是 4 的倍数）时，末位字符其实和下一段的前几位共用一个字节，单独解必然错。

正确做法是**先拼成一个连续 base64 串，一次解码**：

```python
import base64
segs = ['ZmxhZ3tlNj', 'YyYWMxNTRj', 'YTM3NmUxYz', 'AwMWVlOGJi', 'ZTgxMzE4Yn0K']
s = ''.join(segs)
print(len(s), len(s) % 4)          # 52 0
print(repr(base64.b64decode(s)))
```

真实输出：

```
52 0
b'flag{e662ac154ca376e1c001ee8bbe81318b}\n'
```

拼接后长度 52，正好是 4 的倍数，解出 39 字节：`flag{...}`（38 字节）外加一个换行符。

### 3.5 第五步：验证格式

`flag{` + 32 位十六进制 + `}` = 38 字符，长度与内容都规范，符合"32 位 hex"的常规形态。这也解释了为什么最后一段是 12 字符而不是 10：末尾的 `}\n` 把最后一段撑长了。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| DNS 隧道 / DNSLog | 把数据编码进查询名，由权威服务器记录 | 出网只放行 DNS 时唯一的隐蔽通道 | 外带、盲注回显、无回显 RCE |
| 标签长度约束 | 单个 label ≤ 63 字节，整名 ≤ 253 字节 | 解码时要按"每段约 10 字符"切 | 一切分片外带协议 |
| base64 段对齐 | 段长非 4 的倍数时逐段解必错 | 本题最能骗人的一步 | 分片传输、日志拼接、邮件附件 |
| A / AAAA 双查 | 每个名字会被查两次（IPv4 + IPv6） | 不去重会让片段翻倍 | Windows 客户端的默认行为 |
| 系统搜索域后缀 | 短名字会被追加 `.localdomain` 等 | 会污染标签比对 | 内网抓包、Windows DNS 解析 |

## 五、踩坑与陷阱

1. **依赖 pyshark 而没有 tshark**。报的是 `ModuleNotFoundError`，真因是缺 tshark；要么装 Wireshark 并配 `tshark_path`，要么走零依赖手写解析。
2. **逐段解码**。第 2、4 段会解出乱码，很容易误判成"还有一层加密"从而跑偏。
3. **把重复前缀也拼进去**。`ZmxhZ3`（7 字符）一旦算进串里，总长变成 59，`59 % 4 = 3`，解码直接崩，或者得到一个很像但缺字的假 flag。
4. **把 `root` / `Z` 当数据**。它们是平台探活与起止标记，字符集也像 base64，混进去会污染结果。
5. **不去重**。每个标签出现两次（A + AAAA），不去重就会得到 `flag{e6flag{e6...` 这类重复串。
6. **忘了 `.localdomain`**。`YyYWMxNTRj.i6ov08.dnslog.cn.localdomain` 与正常标签是同一个，直接按 `endswith('.i6ov08.dnslog.cn')` 过滤会漏掉它。

## 六、赛场 20 分钟行动清单

1. 看协议构成：只有 UDP/53 没有 TCP → 优先怀疑 DNS 隧道。
2. 提取全部查询名（tshark 一行，或自己解），按帧号排序。
3. 找公共后缀（这里 `i6ov08.dnslog.cn`），剥掉。
4. 判断哪些是哨兵（`root`、`Z`、纯域名本身），哪些是载荷（base64 字符集、长度稳定）。
5. 去重 → 按时间拼成一整串 → 一次 base64 解码 → 校验 `flag{}` 形态。
   > 超过 15 分钟还没解出可读文本，先怀疑"拼接顺序/重复段"，而不是怀疑还有加密。

## 七、附件与脚本

现场目录 `D:\XiaoMibook\CTF学习\pcap4\`：

| 文件 | 作用 |
|---|---|
| `dns.pcapng` | 原始抓包（178 帧 / 21.9 KB） |
| `dns_parse.py` | 零依赖 pcapng + DNS 解析，输出会话、查询类型、唯一名、应答、时间线 |
| `dns_tunnel.py` | 只取查询、剥后缀、列标签、试拼接解码 |

复现命令：

```powershell
cd D:\XiaoMibook\CTF学习\pcap4
python dns_parse.py      # 概览：64 个 DNS 包、10 个唯一查询名
python dns_tunnel.py     # 时间线 + 标签去重 + 拼接解码
```

两个脚本都只读 `dns.pcapng`、只往标准输出打印，不改动原文件。`dns_tunnel.py` 的拼接段默认把 `root` / `Z` 过滤掉，但**没有**自动剔除 `ZmxhZ3` 这个重复前缀——真正落地时那步要自己补，否则会得到带重复片段的假串。
