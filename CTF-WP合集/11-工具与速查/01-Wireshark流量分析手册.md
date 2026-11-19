# Wireshark 流量分析手册（CTF 杂项）

> 适用人群：CTF Misc 新手
> 核心思想：**先全局统计，再抓关键点（Follow Stream），最后导出文件**

---

## 一、两个概念：捕获过滤器 vs 显示过滤器

| 类型 | 位置 | 作用 | 特点 |
|------|------|------|------|
| 捕获过滤器 (Capture Filter) | 捕获前，工具栏左侧下拉框 | 只抓符合规则的数据包 | 用的是 BPF 语法（libpcap），**不是** Wireshark 语法 |
| 显示过滤器 (Display Filter) | 捕获后，主界面顶部输入框 | 从已抓到的包里过滤显示 | 用的是 Wireshark 语法，**做题主要用这个** |

⚠️ 做题时绝大多数情况只用**显示过滤器**，因为包已经抓完了。

---

## 二、显示过滤器基础语法

```
语法格式：  字段 运算符 值
示例：      ip.src == 192.168.1.1

比较运算符：
  ==   等于          !=  不等于
  >    大于          <   小于
  >=   大于等于      <=  小于等于
  contains   包含（子串匹配，字符串/字节）
  matches    正则匹配

逻辑运算符：
  and (&&)   与
  or  (||)   或
  not (!)    非
括号 () 可组合：
  (ip.src == 1.1.1.1 or ip.dst == 1.1.1.1) and http
```

常用字段提示：输入时 Wireshark 会自动补全，输入 `ip.`、`tcp.`、`http.` 后按提示选即可。

---

## 三、最常用过滤器速查表

### 1. 协议大类
```
http         只看 HTTP        https 或 tls   只看加密流量（一般看不出内容）
dns         只看 DNS 查询     ftp / ftp-data   看 FTP 控制/数据
tcp         只看 TCP 包       udp           只看 UDP 包
icmp        Ping 流量         arp           只看 ARP
usb         只看 USB 流量     btle / bluetooth 蓝牙
smtp / pop / imap   邮件协议
ssh         远程登录
```

### 2. IP 和端口
```
ip.addr == 192.168.1.100        源或目的 IP 是这个（最常用）
ip.src == 192.168.1.100         只看源 IP
ip.dst == 192.168.1.100         只看目的 IP

tcp.port == 80                  源或目的端口是 80
tcp.dstport == 80               只看目的端口
udp.port == 53
tcp.port >= 10000               端口范围
```

### 3. HTTP（CTF 出现率最高）
```
http.request                      只看 HTTP 请求
http.request.method == "GET"      只看 GET 请求（也常用 "POST"）
http.host == "example.com"        只看访问某域名的请求
http.request.uri                  只看请求的 URI（路径）
http.response.code == 200         只看 200 响应（404/302 同理）
http.response.code >= 400         只看错误响应
http.content_type == "image/png"  只看图片响应（找隐藏文件用）
http.file_data                    只看响应体内容（找 flag 用）
http.user_agent                   看 UA（可能藏马脚）
http.cookie                       看 Cookie
http.authorization                看认证信息（可能明文密码）
```

### 4. TCP / 流
```
tcp.stream == 0                  只看第 0 条 TCP 流（数字可改）
tcp.flags.syn == 1               只看 SYN（三次握手）
tcp.flags.reset == 1             只看 RST
tcp.len > 0                      只看带数据的包（过滤 ACK 之类空包）
```

### 5. DNS
```
dns                                   所有 DNS 包
dns.flags.response == 0               只看查询请求（分析隧道主要看这个）
dns.flags.response == 1               只看响应
dns.qry.name contains "flag"          查询的域名包含 flag
dns.qry.name contains "dnslog"        找 dnslog.cn / ceye.io 这类回带平台
dns.qry.type == 16                    只看 TXT（隧道常用，单包载荷最大）
dns.qry.type == 1                     只看 A 记录
dns.qry.name matches "[A-Za-z0-9]{30,}"   超长子域名（隧道最典型特征）
```

**技巧**：右键包列表的列头 → `列首选项`（Column Preferences）→ 添加一列，字段填 `dns.qry.name`。这样查询名直接显示在列表里，不用一个个点开看，60 个包的隧道题 10 秒就能扫完。

### 6. 字符串搜索（找 flag 的核心手段）
```
frame contains "flag"             任何包里有 "flag" 字样（也可搜 "key" "ctf"）
frame contains "flag{"            直接搜 flag 格式
tcp.payload contains "password"   在 TCP 数据里搜
http contains "admin"             在 HTTP 里搜
```

### 7. USB（键盘/鼠标流量题）
```
usb.transfer_type == 0x01         控制传输（键盘鼠标数据一般在这）
usbhid.data                       只看 USB HID 数据（键盘按键原始数据）
usb.device_address == 1           按设备筛选
```

---

## 四、必会的 5 个操作（不是过滤器的"操作"）

### 1. 追踪流（Follow Stream）⭐最关键
右键任意包 → **Follow** → **TCP Stream**（或 HTTP Stream / UDP Stream）
快捷键：`Ctrl + Alt + Shift + T`

作用：把一整条会话的内容拼接显示出来，**明文内容（flag、密码、文件内容）基本上都靠它看**。左上角下拉框可以切换不同的流，底部可以切换显示格式（ASCII / Hex / Raw）。

### 2. 导出对象（Export Objects）
**File → Export Objects → HTTP**（或 SMB、TFTP 等）

作用：把流量里传输过的**所有文件**一键导出，比如 HTTP 传的图片、压缩包。CTF 里"从流量里提出一张图"全靠它。

### 3. 统计视图（Statistics）
- **Statistics → Protocol Hierarchy**：看流量里有哪些协议，快速判断大概是什么题（有 DNS 大量记录 → 可能是 DNS 隧道；有 FTP → 可能传了文件）
- **Statistics → Conversations**：看会话列表，找大数据量的会话（大流量 = 可能传了文件/图片）
- **Statistics → Endpoints**：看所有 IP/端口

### 4. 全局搜索（Ctrl + F）
搜索框输入 `flag`，左侧选 "Packet details" 或 "String"，直接在所有包里搜字符串。比过滤快，适合先定位。

### 5. 着色规则 & 保存过滤器
- 视图 → 着色规则：可自定义高亮
- 过滤框输入后，点旁边的 **☆ 收藏按钮** 保存常用过滤器，下次直接点

---

## 五、CTF 常见题型解题思路（套路）

### 题型 1：直接在流量里找 flag
```
思路：Ctrl+F 搜 "flag" → 没有就 frame contains "flag{" → 再没有就 Follow TCP Stream 逐个流看
```

### 题型 2：HTTP 传了一个隐藏文件
```
思路：File → Export Objects → HTTP 全导出 → 一个个看（图片/zip/压缩包）
      配合 http.content_type == "image" 过滤
```

### 题型 3：FTP 传文件
```
思路：看 ftp 命令（USER/PASS 可能明文密码）→ ftp-data 里的数据
      导出对象选 FTP，或 Follow TCP Stream 看数据段（图片会以二进制显示，可 Hex 导出）
```

### 题型 4：DNS 隧道 / DNS 藏数据
```
思路：dns.qry.name 一条条看，域名前缀的 base32/base64 子串拼起来解码
      可用 tshark 批量提取域名：
      tshark -r dns.pcapng -Y "dns.flags.response==0" -T fields -e dns.qry.name

三步走：
  ① 剥后缀：把公共域名（如 .i6ov08.dnslog.cn）去掉，只留前面的子域名
  ② 按时间排序 + 去重
  ③ 拼成一个长字符串再整体解码（关键！不能一段段解，见第八章踩坑）
```

**怎么一眼认出 DNS 隧道**（满足任意两条基本就是）：

| 特征 | 正常 DNS | DNS 隧道 |
|---|---|---|
| 子域名长度 | 短，可读（`www`、`mail`） | 长、乱、像 base64（`ZmxhZ3tlNj`） |
| 查询频率 | 偶尔 | 同一父域高频，几十上百次 |
| 域名归属 | 常见站点 | 陌生域 + `dnslog.cn`/`ceye.io`/`oast.*` |
| 响应内容 | 真实公网 IP | 统一返回 `127.0.0.1` 或 `0.0.0.0` |
| 记录类型 | A / AAAA / CNAME | 大量 TXT / NULL / AAAA |

**DNSLog 是什么**：`dnslog.cn` 这类平台给每人一个随机子域（如 `i6ov08`），任何 `xxx.i6ov08.dnslog.cn` 的查询都会被平台记录下来。渗透里用来验证"盲注/RCE 到底有没有执行"——命令结果塞进子域名查出来，攻击者再去平台页面看日志。CTF 里就是把 flag 这样一段段带出去。

### 题型 5：USB 键盘流量（敲了什么键）
```
思路：usbhid.data 提取每个包的按键码 → 按键码对应表还原成字符（网上有脚本）
      对于键盘流量，通常用 tshark 导出：
      tshark -r keyboard.pcapng -Y "usbhid.data" -T fields -e usbhid.data
      然后用 Python 脚本把 HID 键码转成字符
```

### 题型 6：图片藏在流量里（比如 HTTP 响应体直接是图片）
```
思路：Follow HTTP Stream 看响应头 content-type → 用 "Raw" 格式保存响应体 → 改后缀为 .png/.jpg
      或者用导出对象直接导出
```

---

## 六、tshark 命令行速查（Wireshark 自带，写脚本批量处理用）

```bash
# 列出所有包的基本信息
tshark -r capture.pcapng

# 按显示过滤器过滤并显示字段
tshark -r capture.pcapng -Y "http.request" -T fields -e http.host -e http.request.uri

# 提取 USB 键盘数据
tshark -r keyboard.pcapng -Y "usbhid.data" -T fields -e usbhid.data

# 提取 DNS 查询域名（最常用）
tshark -r dns.pcapng -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# 带帧号 + 类型，方便对照时间线
tshark -r dns.pcapng -Y "dns.flags.response == 0" -T fields -e frame.number -e dns.qry.name -e dns.qry.type

# 只看 TXT 记录（隧道载荷最常藏这里）
tshark -r dns.pcapng -Y "dns.qry.type == 16" -T fields -e dns.qry.name -e dns.txt

# 统计查询次数，找高频域名（Linux/WSL）
tshark -r dns.pcapng -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# 同上，PowerShell 版
# & tshark ... | Group-Object | Sort-Object Count -Descending | Select-Object Count,Name

# 导出 HTTP 对象
tshark -r capture.pcapng --export-objects "http,./exported/"

# 看协议统计
tshark -r capture.pcapng -z io,phs
```

---

## 七、做题流程模板（照做就行）

```
1. 打开 pcap → 先看 Statistics → Protocol Hierarchy（判断题型）
2. Ctrl+F 搜 "flag" 定位（没有就换 "key" "ctf" "{")
3. 对可疑会话右击 → Follow TCP Stream 逐个看
4. File → Export Objects → HTTP 导出文件，检查隐藏文件
5. 如果流量里有大文件传输（大包），看 Conversations 找大流量会话
6. 对应题型套路处理（见第五节）
7. 拿到 flag 前先解码检查：base64 / hex / URL 编码都试一下
```

---

## 八、DNS 隧道实战复盘（dns.pcapng）

> 题例：`dns.pcapng`（178 帧 / 21.9 KB），**flag{e662ac154ca376e1c001ee8bbe81318b}**
> 环境：`192.168.181.128` → DNS 服务器 `192.168.181.2:53`

### 1. 先判断题型

`统计 → 协议分级` 里 DNS 占比异常 → 基本坐实。这道题 178 个包里只有 64 个 DNS 包，其余是噪音（NetBIOS 的 `Pdsdt.local`、ARP 等）。

关键特征是：**所有查询都指向同一个陌生父域 `i6ov08.dnslog.cn`**，而且响应统一返回 `127.0.0.1`。

### 2. 提取查询名（两种方式）

**Wireshark GUI**：过滤器 `dns.flags.response == 0`，然后加 `dns.qry.name` 列。

**tshark（更快，结果能直接复制）**：

```powershell
& "D:\Program Files\Wireshark\tshark.exe" -r dns.pcapng `
    -Y "dns.flags.response==0" -T fields -e dns.qry.name
```

输出：

```text
i6ov08.dnslog.cn                         测试连通性
root.i6ov08.dnslog.cn                    测试
Z.i6ov08.dnslog.cn                       测试
ZmxhZ3tlNj.i6ov08.dnslog.cn              数据 1
ZmxhZ3.i6ov08.dnslog.cn                  冗余（迷惑段）
YyYWMxNTRj.i6ov08.dnslog.cn              数据 2
YyYWMxNTRj.i6ov08.dnslog.cn.localdomain  数据 2（带搜索域后缀）
YTM3NmUxYz.i6ov08.dnslog.cn              数据 3
AwMWVlOGJi.i6ov08.dnslog.cn              数据 4
ZTgxMzE4Yn0K.i6ov08.dnslog.cn            数据 5
```

### 3. 剥离 + 去重 + 拼接

```python
import base64

segs = ['ZmxhZ3tlNj', 'YyYWMxNTRj', 'YTM3NmUxYz', 'AwMWVlOGJi', 'ZTgxMzE4Yn0K']
s = ''.join(segs)
# ZmxhZ3tlNjYyYWMxNTRjYTM3NmUxYzAwMWVlOGJiZTgxMzE4Yn0K
print(base64.b64decode(s))
# b'flag{e662ac154ca376e1c001ee8bbe81318b}\n'
```

### 4. 四个坑（都是实际踩到的）

**坑 1：不能一段段解**

`ZmxhZ3tlNj` 是 10 个字符，不是 4 的倍数，单独解码会得到 `flag{e6` 后面跟半截。base64 每 4 字符 = 3 字节，**必须在字符串层面先拼好再解**。

```python
# ❌ 错：逐段解
for seg in segs: base64.b64decode(seg + '=' * (-len(seg) % 4))

# ✅ 对：先拼再解
base64.b64decode(''.join(segs))
```

**坑 2：有冗余迷惑段**

`ZmxhZ3` 单独解出来是 `flag`，它是 `ZmxhZ3tlNj` 的前缀。如果把它也拼进去，就变成 `flag{e6**flag**...`，解码直接失败。

**判断方法**：拼完先看开头是不是 `flag{`，如果中间出现第二次 `flag`，说明有重复段，去掉它。

**坑 3：`.localdomain` 后缀**

```
YyYWMxNTRj.i6ov08.dnslog.cn.localdomain
```

这是 Windows 的 DNS 搜索域（search domain）自动补的。提取时要按 `.i6ov08.dnslog.cn` 截断，否则子域名会带上 `localdomain`。

**坑 4：重复查询**

同一段数据会出现 2～4 次（DNS 重传 + A/AAAA 双查询）。必须去重，否则拼出来是 `flag{e6flag{e6...`。

**去重原则**：按时间顺序，保留**第一次出现**，且**与已有段不互为前缀**。

### 5. 可复用脚本

```python
import base64, re

queries = """粘贴 tshark 输出""".splitlines()
parent = 'dnslog.cn'

segs = []
for q in queries:
    q = q.strip()
    if not q or parent not in q:
        continue
    sub = q.split('.' + parent)[0]          # 剥掉父域和后缀
    if not re.fullmatch(r'[A-Za-z0-9+/]+', sub):   # 跳过 root/Z 这类测试
        continue
    if len(sub) <= 3:                        # 太短的也是测试
        continue
    if any(sub.startswith(x) or x.startswith(sub) for x in segs):  # 互为前缀 → 重复
        continue
    segs.append(sub)

print('segments:', segs)
print(base64.b64decode(''.join(segs)))
```

### 6. 这道题的时间线特征

查询间隔从几十秒到几万秒不等（整段横跨 89 小时），说明不是人类手动操作，是**脚本按时间窗口定时外带**。真实场景里，攻击者会把 `cat /flag | base64` 的结果切成固定长度，逐段查出去。

---

## 九、练习推荐

- **NSSCTF**：搜索 "流量分析" 标签，简单题起步
- **BUUCTF**：杂项 → 流量分析模块
- 本地练习：可以用 Wireshark 抓自己浏览器上某个网站的过程，练过滤