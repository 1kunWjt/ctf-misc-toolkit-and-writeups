# EZtraffic — Writeup

> DASCTF 赛制 · 分类：Misc（流量分析 → SMB2 取证 → 加密压缩包） · 难度：★★★★☆

| 项目 | 内容 |
|---|---|
| 题目名 | EZtraffic |
| 分类 | Misc / 流量分析（pcapng → SMB2 → WinZip AES → 拼图二维码） |
| 附件 | `EZtraffic.pcapng`（203508 字节，1 个网卡、322 个包） |
| 一句话 | 整个 SMB2 会话只干了一件事：从 `\\10.10.1.81\secret` 读走一个 AES 加密的 `final_out.zip`，密码提示藏在 zip 注释里 |
| 结果 | 未完成（见「卡点与正解方向」），已把 88530 字节的加密 zip 完整复原 |

**最终答案**

```
未完成 —— 没有拿到 DASCTF{...} 明文。
已确认：pcapng 里只有 SMB(445) 与 RDP(3389)，无 HTTP；SMB2 READ 复原出 final_out.zip = 88530 字节；
        zip 内 100 张 PNG（共 67750 字节，单张 364~1416 字节）全部 WinZip AES-256 加密；
        密码提示 = zip 注释 "NTLM v2 plaintext + \d{5}"。
卡点：NTLMv2 明文未爆破（本机无 rockyou 词表、无 hashcat），拿不到 zip 密码。
```

## 一、题目长什么样（先建立直觉）

198 KB 的 `EZtraffic.pcapng`。环境里没有 Wireshark、tshark、scapy，所以第一道坎是**自己把 pcapng 解析出来**。最便宜的侦察——按块类型走一遍 + 五元组分流：

```
[*] file size = 203508 bytes
[OK] SectionHeaderBlock @0x0000  byte-order=LE  version=1.0  blocklen=180
[OK] InterfaceDescriptionBlock #0  linktype=1(ETHERNET)  snaplen=262144
[*] blocks = {168627466: 1, 1: 1, 6: 322, 5: 1}      # 168627466 = 0x0A0D0D0A
[*] packets = 322 ; flows = 8        # 下表只列主要方向，另 4 条是对应反向流
    10.10.1.81:445        -> 192.168.227.252:57990   172 pkts   # 主通道
    192.168.227.252:57990 -> 10.10.1.81:445          126 pkts
    192.168.227.252:57986 -> 10.10.1.81:445            6 pkts   # srvsvc 管道
    192.168.227.252:57956 -> 10.10.1.81:3389           3 pkts   # RDP，TLS 加密
```

`168627466` 就是 `0x0A0D0D0A`，Section Header Block 的魔术数，pcapng 的身份证。

**这一刻方向就定了**：445 是 SMB，3389 是 RDP，一个 HTTP 包都没有。题库笔记里"HTTP 响应体里有 GIF/PNG"的猜测是错的——但"多帧图片拼图 + 二维码"这个方向恰恰对了，只是载体不是 HTTP。

## 二、思路总览

```
pcapng 块解析 → 五元组分流 → 445 那条流按 seq 重组成字节流（NBSS 分帧）
  → SMB2 解析：TREE_CONNECT 拿共享名、CREATE 拿文件名、READ 拿数据
  → 按 MessageId 把 READ 请求的 (FileId, offset) 与响应数据配对
  → 复原 final_out.zip（88530 字节）→ WinZip AES-256
  → 注释 "NTLM v2 plaintext + \d{5}" → 去 SESSION_SETUP 挖 NTLMv2
  → 爆破明文 →（明文 + 5 位数字）= zip 密码 → 100 张 PNG → 拼图 → 二维码 → flag
                                                      └── 卡在这里，前面全部打通
```

关键认知：**这不是"流量里藏图片"，而是"流量里传了一个加密压缩包，压缩包里才是图片"**。顺序必须是"先协议、再密码学、最后才拼图"。

## 三、逐步复现

### 3.1 第一步：自己写 pcapng 解析器

pcapng 是"块"堆起来的，骨架一致：`Type(4) + TotalLength(4) + Body(变长，4 字节对齐) + 重复的长度(4)`。要认三种块：SHB `0x0A0D0D0A`（段开头，含字节序魔术 `0x1A2B3C4D`）、IDB `0x00000001`（网卡：`linktype`、`snaplen`、if_name）、EPB `0x00000006`（真正的包：`ifid(4)+ts_high(4)+ts_low(4)+caplen(4)+origlen(4)` 之后才是包数据）。

`4 字节对齐`是唯一要小心的点：块体补齐到 4 的倍数，块长度本身也是 4 的倍数，所以主循环只要 `off += blen` 就永不越界。

```python
while off + 12 <= n:
    btype, blen = struct.unpack_from('<II', data, off)
    if blen < 12 or off + blen > n:          # 长度自校验，坏块立刻停
        break
    body = data[off + 8: off + blen - 4]     # 去掉块头和尾部重复长度
    if btype == 0x00000006:                  # EPB
        ifid, tsh, tsl, caplen, origlen = struct.unpack_from('<IIIII', body, 0)
        packets.append((ifid, (tsh << 32) | tsl, body[20: 20 + caplen]))
    off += blen
```

`linktype=1` 是以太网 → `pkt[12:14]` 是 ethertype（`0x0800`=IPv4）；IP 头 `p[0]>>4==4`、`ihl=(p[0]&0xF)*4`；TCP 头 `doff=(p[12]>>4)*4`。三层都是定长字段，手写 30 行足够。

### 3.2 第二步：TCP 重组 + 魔数扫描（先不看协议语义）

拿到 8 条流后**先不猜协议**：按 `seq` 把载荷拼成字节流，再全文扫文件魔数。出现 `PK\x03\x04` 就说明有文件在传，回头做协议解析才有目标。

```python
def reassemble(segmap):                  # {seq: payload}
    out, cursor = bytearray(), None
    for seq in sorted(segmap):
        p = segmap[seq]
        if cursor is None:
            out += p; cursor = seq + len(p); continue
        if seq + len(p) <= cursor:  continue       # 完全重复的段丢掉
        if seq > cursor:  out += b'\x00' * (seq - cursor)   # 空洞补 0，保留偏移
        out += p[cursor - seq:]; cursor = seq + len(p)
    return bytes(out)
```

服务端方向（161689 字节）：

```
[*] NBSS frames = 61, desync events = 0
    CREATE RESP 15   READ RESP 11   CLOSE RESP 10   QUERY_INFO RESP 8   IOCTL RESP 5
    WRITE RESP 4     NEGOTIATE RESP 2  SESSION_SETUP RESP 2  TREE_CONNECT RESP 2
[*] printable strings len>=4 (first 60 unique):
    @1497 '\\PIPE\\srvsvc'    @7081 'final_out/PK'    @7121 'final_out/0vP5BE3z.png'
```

`desync events = 0` 说明 NBSS（NetBIOS Session Service）分帧干净：每帧头 4 字节 = `类型(1) + 长度(3，大端)`，`0x00` 普通会话消息、`0x81~0x85` 请求/响应/保活。**服务端 161689 字节切成 61 帧，客户端 10600 字节也是 61 帧**——一来一回正好对应，这是按 MessageId 配对的物理基础。

### 3.3 第三步：SMB2 解析，把 READ 响应拼成文件

SMB2 头固定 64 字节：`0x00` `\xfeSMB`、`0x08` Status、`0x0C` Command（5=CREATE、8=READ、14=QUERY_DIRECTORY）、`0x10` Flags（bit0=1 表示响应）、`0x14` NextCommand、`0x18` MessageId、`0x24` TreeId、`0x28` SessionId。

**核心难点：READ 响应里既没有 FileId 也没有文件偏移**，只有 `DataOffset/DataLength`，必须靠 `MessageId` 回去找对应的 READ 请求，读出 `(FileId, offset)`，再把数据写到该 FileId 镜像的该偏移上。

```python
def parse_read_req(m):                       # 请求里才有 offset / FileId
    return (struct.unpack_from('<I', m, 64 + 4)[0],
            struct.unpack_from('<Q', m, 64 + 8)[0], m[64 + 16: 64 + 32])

def parse_read_resp(m):                      # 响应里只有数据
    return m[m[66]: m[66] + struct.unpack_from('<I', m, 68)[0]]
```

另一个坑：SMB2 **文件名是 UTF-16LE**，按 ASCII 解会得到 `f\x00i\x00n\x00a\x00l\x00...`，必须 `decode('utf-16-le')`。真实输出（节选）：

```
[OK] CREATE resp mid=38 fid=e5000000000000001d000000ffffffff name='final_out.zip'
[OK] READ  mid=39 off=0     len=16384  fid=e5... -> size=16384
[OK] READ  mid=40 off=86016 len=2514   fid=e5... -> size=88530      <-- 有空洞
[OK] CREATE resp mid=45 fid=ed0000000000000025000000ffffffff name='final_out.zip'
[OK] READ  mid=52 off=0     len=88530  fid=ed... -> size=88530      <-- 一次读满
[*] distinct FileIds = 14
```

| 事实 | 值 |
|---|---|
| TREE_CONNECT | `\\10.10.1.81\secret`；另一条 `\\10.10.1.81\IPC$` + `srvsvc` 管道 |
| QUERY_DIRECTORY | `FINAL_~1.ZIP`、`final_out.zip`、`.`、`..` |
| CREATE | `final_out.zip` 被打开 **3 次**（mid=38/45/64），另有 `desktop.ini`（干扰项） |

**最省力的捷径**：三次打开里只有 `mid=52` 是 `off=0 len=88530` 一次读满——处理这一条 READ 响应就能无损复原整个 zip；另外两次是"读 16384 再跳读 86016/73728"，拼出来是中间带空洞的残图。

### 3.4 第四步：zip 是加密的，密码提示就在注释里

```
[*] zip size = 88530  head=b'PK\x03\x04\x14\x00\x00\x00'
[*] tail  = b'Z,\x01\x00\x1a\x00NTLM v2 plaintext + \\d{5}\x00'
[OK] entries = 101   [*] total uncompressed = 67750, min/max png = 364/1416
[*] compress types = [0, 99]     # 随后 testzip() 抛：File ... is encrypted, password required
```

`[*] tail` 那行很有意思：zip 最后 26 字节**就是注释本身**，`NTLM v2 plaintext + \d{5}` 裸奔在文件尾，不用解析 EOCD，`strings` 就能看见。`compress_type = 99` 是 **WinZip AES**，参数在额外字段 `0x9901` 里：

```
     [AES] version=2 vendor=b'AE' strength=3 real_method=0 keylen=32 saltlen=16
     salt = b0d81edc70943b2f58b3a8fac17f4adb    verifier = d610
     ciphertext starts @ 121, len = 829 (csize - 16 - 2 - 10)
```

`strength=3` = AES-256，`real_method=0` = 内部明文存储（只被 AES 加密）。这串数字的价值是给了一个**极快的验密码点**：`PBKDF2-HMAC-SHA1(pw, salt, 1000, 66)` 的前 32 字节是 AES key、中间 32 是 HMAC key、最后 2 字节是 verifier（比对 `d610`）。到这里骨架全清楚：**100 张 PNG（10×10）+ 一个加密 zip + 一条 NTLMv2 握手**，100 这个数基本锁死"网格拼接"的设计意图。

### 3.5 第五步：把 NTLMv2 从 SESSION_SETUP 里挖出来

`SESSION_SETUP` 的 security blob 里是 NTLMSSP 消息（`NTLMSSP\0` + 4 字节类型，2=CHALLENGE、3=AUTH）。全包扫 UTF-16 字符串能直接看到身份：`MicrosoftAccount` + `rockyou` + `BARRY`。

```python
i = m.find(b'NTLMSSP\x00')
if int.from_bytes(m[i+8:i+12], 'little') == 2:
    chal = m[i + 24:i + 32]                                  # 8 字节 server challenge
elif int.from_bytes(m[i+8:i+12], 'little') == 3:
    def sec(o):                                              # 字段布局 (len, maxlen, offset)
        ln = int.from_bytes(m[i+o:i+o+2], 'little')
        bo = int.from_bytes(m[i+o+4:i+o+8], 'little')
        return m[i+bo:i+bo+ln]
    auth = dict(dom=sec(28).decode('utf-16-le'),
                usr=sec(36).decode('utf-16-le'), nt=sec(20))
```

```
[OK] user='rockyou' domain='MicrosoftAccount'
[OK] server_challenge = 4936df20962cae6d
[OK] NTProofStr       = db12ced50faf52f141636e80205e8f28    [OK] blob len = 382
[*] rate = 13353 candidates/s (74.9 us each)
```

`domain=MicrosoftAccount` + 用户名 `rockyou` 几乎就是在喊"去 rockyou 词表里找"。而 `blob len = 382` 必须一字节不差——HMAC 覆盖整个 blob，尾巴多一个 `\x00` 就永不出解。

### 3.6 第六步：手写 MD4 做 NTLMv2 校验

`hashlib.new('md4')` 直接报错（OpenSSL 3 把 MD4 挪进 legacy provider），只能自己写 RFC 1320（实现略，逻辑就是 R1 `F=(b&c)|(~b&d)`、R2 `G=(b&c)|(b&d)|(c&d)`、R3 `H=b^c^d`，配 `3/7/11/19`→`3/5/9/13`→`3/9/11/15` 三组循环移位）。

自检不能省（错一个移位就全废）：`MD4(b'abc') = a448017aaf21d8525fc10ae87aa6729d`、`NT('password') = 8846f7eaee8fb117ad06bdd830b7586c` 两条对上后，验证只有三行：`NT=MD4(UTF-16LE(pw))` → `v2hash=HMAC-MD5(NT, UTF-16LE(UPPER(user)+domain))` → `proof=HMAC-MD5(v2hash, chal+blob)`，比对 `proof` 即可。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| pcapng 块结构 | SHB / IDB / EPB + 4 字节对齐 | 没有 tshark 时唯一能进门的钥匙 | 任何 pcapng 取证、自研流量工具 |
| NBSS 分帧 | 4 字节头 `类型 + 24bit 长度` | SMB over TCP 的消息边界，定错就全错位 | SMB1/2/3、NetBIOS 题 |
| MessageId 配对 | 响应不带上下文，靠 mid 找请求 | READ 响应的 FileId/offset 只能这样补 | DCERPC、LDAP 等请求响应分离的协议 |
| WinZip AES (99) | 额外字段 `0x9901` + salt + verifier + HMAC | verifier 只有 2 字节，是验密码的最快点 | 加密 zip、7z、RAR5 取证 |
| NTLMv2 | challenge + HMAC-MD5 的应答协议 | 明文不可逆，只能字典/掩码爆破 | 内网取证、Responder 流量 |
| 网格拼图 | 把 N 小块按顺序铺回大图 | 100 = 10×10，是出题人给的结构提示 | 图片碎片题、二维码分片题 |

## 五、踩坑与陷阱

| 坑 | 表现 | 教训 |
|---|---|---|
| 相信笔记的"HTTP 里有 GIF" | 扫完整包没有一个 HTTP，白写半天 HTTP 解析 | 先量流量再定方案：全是 445/3389 就立刻放弃 HTTP |
| 想直接找 `\x89PNG` 魔数 | 只有加密后的随机字节，PNG 头一个都找不到 | 加密容器里没有魔数，得先解决密码 |
| SMB2 文件名按 ASCII 解 | 得到 `f\x00i\x00n\x00a\x00l\x00...` | 一律 UTF-16LE |
| 以为 READ 响应自带偏移 | READ 响应结构里根本没有 offset / FileId | 必须按 `MessageId` 回查请求 |
| 只拼 16 KB 分片 | `mid=39/40/41` 拼出来带空洞，zip 打不开 | 先看所有 READ 长度，发现 `mid=52` 一次读满 88530 |
| blob 尾巴多个 `\x00` | HMAC 覆盖全 blob，错 1 字节就永不命中 | 反复核对 `blob len`，本题应为 382 |
| 按五元组分流写出重复文件 | `s1` 报 8 条流，`s2` 写出 17 个 flow 文件且内容相同 | 拼接前按内容哈希或 `(五元组, seq)` 去重 |

## 六、赛场 20 分钟行动清单

1. **0~3 min**：写 30 行 pcapng 块解析，打印块直方图 + 五元组流表。**看到 445 就把 HTTP 脚本全删掉。**
2. **3~8 min**：TCP 按 seq 重组 → NBSS 分帧 → 打印 SMB2 命令直方图 + 可打印字符串里的文件名，应立刻看到 `final_out/xxxx.png`。
3. **8~14 min**：写 CREATE / READ 配对，优先找"一次读完"的那条 READ。
4. **14~18 min**：解析 zip（EOCD 注释、`0x9901`、salt/verifier），确认 WinZip AES 后马上去 `SESSION_SETUP` 挖 NTLMSSP 三元组。
5. **18~20 min**：有 hashcat + rockyou 就 `hashcat -m 5600` 一条命令；没有就先记下 `\d{5}`，转去写别的题。
> 超过 30 分钟还卡在 NTLMv2 明文上就跳题——这步是算力/词表门槛，没有思路捷径。

## 七、附件与脚本

原始附件：`files/tempdir/MISC附件/EZtraffic.pcapng`（203508 字节）。真实跑过的脚本都在挑战目录 `solve/`（纯标准库）：`s1_pcapng_parse.py`（块解析 + 五元组）、`s2_reasm.py`（TCP 重组 + 魔数扫描）、`s3_smbtrace.py` / `s3b_frames.py`（NBSS 分帧 + 命令直方图）、**`s4_smb2_extract.py`（核心：按 MessageId 复原文件）**、`s5_unzip.py` / `s9_zipinfo.py` / `s9b_zipentry.py`（zip 与 AES 参数）、`s6_strings_all.py`（全包字符串普查）、`s10_md4_ntlm.py`（MD4 + NTLMv2 校验）、`s11_crack_ntlm.py`（字典爆破）、`s12_ntlm_grab.py`（提取参数 + 测速）。

```powershell
$env:PYTHONIOENCODING="utf-8"
python solve\s1_pcapng_parse.py "files\tempdir\MISC附件\EZtraffic.pcapng"
python solve\s2_reasm.py "files\tempdir\MISC附件\EZtraffic.pcapng" solve\out_streams
python solve\s4_smb2_extract.py solve\out_files solve\out_streams\flow12_*.bin solve\out_streams\flow13_*.bin
```

## 卡点与正解方向

### 已确认（可复跑，全部有输出）

1. **通道**：SMB2，共享 `\\10.10.1.81\secret`，被读走的唯一文件是 `final_out.zip`。
2. **文件本体**：88530 字节，来自 `mid=52` 的 `off=0 len=88530` READ 响应；`PK\x03\x04` 头完整、EOCD 完整、101 个条目全部可枚举——**文件完好，不是残缺拼接**。
3. **加密**：WinZip AES-256（strength=3 / keylen=32 / saltlen=16），首张 PNG 的 `salt=b0d81edc70943b2f58b3a8fac17f4adb`、`verifier=d610`、密文偏移 121、长 829；`real_method=0`，拿到密码后是纯 AES-CTR。
4. **密码格式**：zip 注释 `NTLM v2 plaintext + \d{5}`，候选空间 `|词表| × 10^5`。
5. **明文来源**：同包 NTLMSSP 三元组已完整取出（`rockyou` / `MicrosoftAccount` / challenge `4936df20962cae6d` / NTProofStr `db12ced5…` / blob 382），校验器与 RFC 1320 向量均自测通过。

### 卡在哪

**卡在"把 NTLMv2 的明文求出来"。** 本机纯 Python 校验速度 **13353 candidates/s**（74.9 µs 一次：两次 MD4 + 一次 HMAC-MD5）。自带 217 个高频弱口令（rockyou 前排 + 包里捡到的 `rockyou`/`barry`/`final_out`/`dasctf`）跑完 433 次，**`[FAIL] not found in this wordlist`**。上 `\d{5}` 掩码是 `217 × 10^5 ≈ 2.17e7` 次 ≈ **27 分钟**，但前提是明文就在这 217 个词里，而它显然不在（否则纯单词那轮就命中了）。环境无 `hashcat`（mode 5600 一秒几百万）、无 `john`、无 `rockyou.txt`、无网络——**这是算力/词表门槛，不是思路门槛**。

### 正解方向（按性价比）

1. **最直接**：找一台有 hashcat 的机器，把 NTLMv2 整成 5600 格式 `rockyou::MicrosoftAccount:4936df20962cae6d:<NTProofStr>:<blob hex>`，跑 `hashcat -m 5600 hash.txt rockyou.txt`（或 `-a 3 hash ?a?a?a?a?a?a`）。拿到明文 `W` 后，zip 密码 = `W + 五位数`，最多 10 万次 PBKDF2（用 `verifier` 比对，约 0.3 ms/次，30 秒内出结果）。
2. **没词表时**：自造候选集。用户名就是 `rockyou`，明文几乎必然是 rockyou 榜上有名的词；把常见英文名/单词（`barry`、`michael`、`sunshine`…）与 `\d{5}` 组合，按词频从高到低跑，把 217 扩到 3000~5000 词就能拉到可用成功率。
3. **换个读法**：`+ \d{5}` 也可能修饰 NTLMv2 明文本身（账户密码 = `词 + 5 位数字`），那就把掩码加在 NTLMv2 爆破上，空间同为 `|词表| × 10^5`，只是校验点从 zip 换成 NTLM。两种读法都要试，先试注释语义。

### 拿到密码之后（纯机械，无需探索）

1. `PBKDF2-HMAC-SHA1(pw, salt, 1000, 66)` → key/HMAC/verifier，verifier 对上 `d610` 即正确；再 AES-CTR 解 100 张 PNG（`real_method=0`，存储法，无需 inflate）。
2. 100 张 PNG **恰好 10×10**、单张 364~1416 字节（极小的黑白块）——这正是"**为什么拼图能拼成二维码**"的原因：二维码本身就是黑白硬边的模块阵列，出题人把它切成 100 个等大方块再打乱文件名（`0vP5BE3z.png` 这种随机串**不含任何顺序信息**）。黑白硬边意味着相邻块像素本来就不连续，所以**不能靠"接缝跳变最小"排序**，得靠二维码的结构约束：三个 7×7 定位图形 → 角块，白静区 → 画布边界。
3. 拼好后按原分辨率导出 PNG 再解码（缩放会糊掉模块边界）。按 DASCTF 惯例明文应为 `DASCTF{...}`。
