# CTF Writeup 合集（总索引）

> 位置：`D:\XiaoMibook\CTF学习\CTF-WP合集`
> 整理：把 2026-10 至 2026-11 期间在本机各个工作区做过的 CTF 题目 WP 全部收进来，按方向分类。
> 打开方式：Typora →「文件 → 打开」→ 选任意 `.md`。图片是相对路径 `../img/xxx.png`，**整个合集目录一起移动**图片才不会丢。

---

## 一、目录结构

```
CTF-WP合集/
├─ 01-Web/   (9 篇)
├─ 02-Crypto/   (14 篇)
├─ 03-Misc-图片与隐写/   (6 篇)
├─ 04-Misc-流量分析/   (8 篇)
├─ 05-Misc-压缩包与文档/   (3 篇)
├─ 06-Misc-OSINT与杂项/   (4 篇)
├─ 07-Reverse/   (3 篇)
├─ 08-Pwn/   (5 篇)
├─ 09-数据安全/   (5 篇)
├─ 10-AI安全/   (1 篇)
├─ 11-工具与速查/   (14 篇)
├─ img/            全部配图（按前缀分组：web01- / stego08- / cryptoA- ...）
├─ src/            各题的真实解题脚本（从原工程复制）
└─ _写作规范.md    统一格式约定
```

---

## 二、题目总表

### Web　`01-Web`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 1 | [NSSCTF · 简单 GET 与 POST —— Writeup](01-Web/01-NSSCTF-简单GET与POST.md) | Web（HTTP 参数分区 + PHP `json_decode`） | `NSSCTF{6739dfeb-ca0e-468c-a070-b7f5e2b00e9e}` | 175 |
| 2 | [NSSCTF · PHP 弱类型 md5 绕过 —— Writeup](01-Web/02-NSSCTF-PHP弱类型md5绕过.md) | Web（PHP 类型混淆 / 弱比较） | `NSSCTF{LOCAL_TEST_array_bypass_ok}` | 171 |
| 3 | [NSSCTF · 文件上传 easyupload1.0（up10ad来康康）—— Writeup](01-Web/03-NSSCTF-文件上传easyupload1.0.md) | Web（文件上传 / MIME 校验绕过） | `NSSCTF{38ee8558-8ff8-49a3-9569-c1e38f0ca06e}` | 220 |
| 4 | [第 3 题 · RealSignin — Writeup](01-Web/03b-RealSignin.md) | 图片像素最低位里藏了一张 **自定义 base64 码表**，得先抽表、再换表解码 | `DASCTF{We1C0me_2_ZJCTF2024!}` | 205 |
| 5 | [NSSCTF · 蚁剑一句话木马 —— Writeup](01-Web/04-NSSCTF-蚁剑一句话木马.md) | Web（webshell 管理工具） | `NSSCTF{e1380502-e78b-4cc7-a781-3300c753c427}` | 270 |
| 6 | [NSSCTF · up10ad 来康康（27076）— Writeup](01-Web/09-NSSCTF-靶场27076.md) | 后端把客户端自填的 `$_FILES['type']` 当白名单，文件段写 `Content-Type: image/jpeg` 就能让 `.php` 落进可执行目录；flag 不在文件系统里，在容器环境变量里。 | `NSSCTF{38ee8558-8ff8-49a3-9569-c1e38f0ca06e}` | 198 |
| 7 | [Web · 21209 端口后门：命令黑名单绕过 —— Writeup](01-Web/12-21209-TCP-shell黑名单绕过.md) | Web / 后门端口（不是 webshell，也不是 pwn） | `NSSCTF{909c5f3f-ffe5-4e79-b351-51000652206b}` | 231 |
| 8 | [Web · 用「WLLM 浏览器」和「本地 IP」骗过三道门 —— Writeup](01-Web/13-NSSCTF-浏览器UA与伪造IP.md) | Web / HTTP 头部伪造（UA 校验 + IP 信任） | `NSSCTF{836d3d92-7ea0-4a6c-b52d-6a4daf44ed53}` | 219 |
| 9 | [QL_again — Writeup](01-Web/15-QL_again.md) | 用 QLExpress 白名单沙箱挡住所有方法调用，逼你从"构造器 / 字段 / 属性 / 内置函数"四条侧路绕出去 | — | 197 |

### Crypto（密码学）　`02-Crypto`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 10 | [RSA 共模攻击 · Crypto Writeup](02-Crypto/02-RSA共模攻击.md) | 同一明文、同一个 n、两个互素的 e → 扩展欧几里得直接还原明文 | `flag{common_modulus_is_free_points}` | 166 |
| 11 | [RSA 低加密指数 · Crypto Writeup](02-Crypto/03-RSA低加密指数.md) | e=3 且明文很短 → `m³ < n`，c 本身就是完全立方数，直接开整数三次方根 | `flag{small_e_no_padding}` | 139 |
| 12 | [RSA 和差分解 · Crypto Writeup](02-Crypto/04-RSA和差分解.md) | 已知 `p+q` 和 `p−q`，用初等代数直接还原 p、q，**不分解 n** | `flag{sum_and_diff_is_arithmetic}` | 126 |
| 13 | [换表 Base64 · Crypto Writeup](02-Crypto/05-换表Base64.md) | Base64 的本质是"6 bit 查表"，换字母表只是换字典，不是加密 | `flag{retable_base64_is_a_30s_job}` | 133 |
| 14 | [RC4 流密码 · Crypto Writeup](02-Crypto/06-RC4流密码.md) | RC4 是流密码，加密解密是同一个函数（异或两次还原） | `flag{rc4_is_just_xor_a_stream}` | 153 |
| 15 | [第 6 题 · myez_encode — Writeup](02-Crypto/06b-myez_encode.md) | `q ≡ p³+ap+b (mod P)` 把 `n = p·q` 变成 `p` 的四次同余方程，解出 `p` 后才发现 `gcd(e,φ)=3`、`d` 不存在，改成模 `n` 开 9 次方 | `DASCTF{Very_easy_3NC0dE_Is_1t}` | 327 |
| 16 | [多层编码套娃 · Crypto Writeup](02-Crypto/07-多层编码套娃.md) | 按字符集判断编码类型，逐层剥离（rot13 → hex → base64） | `flag{peel_layers_one_by_one}` | 119 |
| 17 | [第 7 题 · SNOW — Writeup](02-Crypto/07b-SNOW.md) | 流密码的密钥流一旦漏出前 44 字、再叠加 `hack()` 漏出的几个 LFSR/FSM 状态，就能代数反解出 512 bit LFSR 与 3 字 FSM，然后重放整条流 | `DASCTF{2bfc1bd3-740e-4b3f-ab9f-9587b1d47209}` | 261 |
| 18 | [叠叠乐（jenga） — Writeup](02-Crypto/08-叠叠乐.md) | 私钥被写成 `d = K·Q + P`，三层泄露把 2048 bit 的未知量一路压到 40 bit，最后靠 XOR 的可分离性做 meet-in-the-middle | `DASCTF{6a4ba557-4fe7-4874-8dad-40e880cb7717}` | 251 |
| 19 | [第 10 题 · MidMath — Writeup](02-Crypto/10-MidMath.md) | 程序把「随机游走恰好走到最优路径」当作通关条件，而 flag 是壳里的一条常量字符串 | `DASCTF{path_16-bit_md5_lowercase_encrypt}` | 256 |
| 20 | [AFCTF · Vigenère 题解](02-Crypto/17-Vigenere唯密文破解.md) | — | — | 99 |
| 21 | [DASCTF · ElGamal「EM-G3」— Writeup](02-Crypto/18-ElGamal-EM-G3.md) | 2048 位安全素数是障眼法：参数完全正确，坏掉的是私钥指数 `x` 的熵——`x = 139`，只有 8 bit，于是在 `x` 的小范围上跑 BSGS 就把 ElGamal 拆了。 | `DASCTF{b4210c04-15d2-4ed8-be4d-742595e0cdca}` | 232 |
| 22 | [字频排序隐写 ·「我flag呢？」 — Writeup + 工具用法](02-Crypto/19-字频排序-我flag呢.md) | **出现次数 = 排序权重**：把花括号里的字符按出现次数从多到少排出来，就是 flag | `NSSCTF{' + body + '}` | 173 |
| 23 | [RecoverWallet（BIP-39 缺词恢复）— Writeup](02-Crypto/20-RecoverWallet-助记词恢复.md) | 12 词缺 1 词只丢了 11 bit，先用 BIP-39 校验和把 2048 个候选压到 131 个，再用派生地址尾号唯一定位 | `DASCTF{地址}` | 220 |

### Misc · 图片与隐写　`03-Misc-图片与隐写`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 24 | [什么楼什么厦? · 图片隐写 Writeup](03-Misc-图片与隐写/01-什么楼什么厦-PNG高度修复.md) | PNG 块结构、IHDR 高度修复、CRC 校验 | `flag{Welcome_to_haobachang}` | 213 |
| 25 | [EZtraffic — Writeup](03-Misc-图片与隐写/05-EZtraffic.md) | 整个 SMB2 会话只干了一件事：从 `\\10.10.1.81\secret` 读走一个 AES 加密的 `final_out.zip`，密码提示藏在 zip 注释里 | `DASCTF{...}` | 261 |
| 26 | [Misc · GIF 第 561 帧里的二维码 —— Writeup](03-Misc-图片与隐写/08-GIF第561帧二维码.md) | Misc / 图片隐写（动图逐帧） | `NSS{The_G1F_ls_T00_b1g}` | 153 |
| 27 | [Misc · 为什么我什么都看不见（PNG 补文件头 + LSB）—— Writeup](03-Misc-图片与隐写/09-为什么我什么都看不见.md) | Misc / 图片隐写 | `NSSCTF{Wlec0me_to_NiSa2022}` | 204 |
| 28 | [Misc · 拼图还原（flag.png_3x3）—— Writeup](03-Misc-图片与隐写/10-拼图还原flag_3x3.md) | Misc / 图片隐写（碎片重组） | `flag{Congratulations on getting this question right}` | 146 |
| 29 | [Bird — Writeup](03-Misc-图片与隐写/17-Bird位平面隐写.md) | `Bird` 是两张 1280×853 PNG（其一反向存储）按字节奇偶交错；卡点是「两图只差 B 通道低幅噪声」与「`flag.zip` 真加密」。 | — | 261 |

### Misc · 流量分析　`04-Misc-流量分析`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 30 | [Misc · stolen.pcapng 流量分析（IP ID 隐蔽信道）—— Writeup](04-Misc-流量分析/06-stolen流量-IPID隐蔽信道.md) | Misc / 流量分析 | `flag{this_is_stolen_secret!!!}` | 186 |
| 31 | [Misc · misc.pcapng（流量里的加密 zip + AES 密文）—— Writeup](04-Misc-流量分析/07-misc流量-AES与加密zip.md) | Misc / 流量分析 + 压缩包 + 对称加密 | `cdusec{happy_every_day}` | 216 |
| 32 | [[LitCTF 2023] easy_shark — 解题记录](04-Misc-流量分析/14-easy_shark木马流量.md) | — | `NSSCTF{w13e5hake_1s_a_900d_t3a771c_t001_a}` | 179 |
| 33 | [菜刀流量 · Writeup（复盘版）](04-Misc-流量分析/15-菜刀流量与flag.rar.md) | pcapng 解析 → 中国菜刀 webshell 流量 → 终端退格还原口令 → RAR5 解密 → HTML 实体解码 | `flag{306bd05d78ccb90d2a442539d70ce4c2}` | 502 |
| 34 | [Boom — Writeup](04-Misc-流量分析/18-Boom-FTP传出ELF.md) | pcap 里用明文 FTP 凭据 + 主动模式下载了一个 ELF 校验器，真正的活是逆向那个 ELF 的判定逻辑。 | `DASCTF{" + f(E[7..22]) + "}` | 258 |
| 35 | [pcap2 · 文件上传 + 冰蝎动态密钥流量 — Writeup](04-Misc-流量分析/20-pcap2-上传木马流量.md) | 木马不是"固定密钥冰蝎"，而是**每次 GET 换一把随机密钥**的变种，密钥就明文写在响应里 | `flag{f4bbc9d39870bc855e1172f994d0912e}` | 229 |
| 36 | [pcap3 · wallpaper 流量（附件不符，未完成） — Writeup](04-Misc-流量分析/21-pcap3-wallpaper流量.md) | 题面要求"导出图片读 EXIF"，而手上这份抓包里**一张图都没有**——先核对附件再谈解法 | `flag{ae58d0408e26e8f26a3c0589d23edeec}` | 199 |
| 37 | [pcap4 · DNS 隧道（dnslog 外带） — Writeup](04-Misc-流量分析/22-pcap4-DNS隧道.md) | flag 被 base64 切段塞进子域名，靠 DNS 查询一段段外带；解码必须**先拼接再解**，逐段解一定错 | `flag{e662ac154ca376e1c001ee8bbe81318b}` | 194 |

### Misc · 压缩包与文档　`05-Misc-压缩包与文档`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 38 | [第 4 题 · 机密文档 — Writeup](05-Misc-压缩包与文档/04-机密文档.md) | 外层是**真 ZipCrypto 加密**（不是伪加密）：12 字节加密头 + 6 万字节密文，只能走已知明文攻击（bkcrack）反解 96 bit 内部密钥 | — | 260 |
| 39 | [Misc · PDF 加密（misc4.pdf）—— Writeup](05-Misc-压缩包与文档/05-PDF加密-misc4.md) | Misc / 文档隐写 | `cdusec{abc_def_ghi}` | 202 |
| 40 | [[CISCN 2018] Picture —— 图片尾部 zlib → base64 → Zip → uuencode 四层 Writeup](05-Misc-压缩包与文档/16-CISCN2018-Picture四层编码链.md) | Misc / 图片隐写（实为**容器追加数据**，不是像素隐写） | `CISCN{2388AF2893EB85EB1B439ABFF617319F}` | 192 |

### Misc · OSINT 与杂项　`06-Misc-OSINT与杂项`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 41 | [第 1 题 · 签到题 — Writeup](06-Misc-OSINT与杂项/01-签到题.md) | 七层 Base 套娃，考的是"你手上有没有能剥 Base92/62/58/45 的工具" | `DASCTF{welcome_to_zjctf_2024}` | 222 |
| 42 | [第 2 题 · 网安知识大挑战 — Writeup](06-Misc-OSINT与杂项/02-网安知识大挑战.md) | 纯前端题：flag 用 CryptoJS AES 加密后拆成 22 片藏在打包 JS 里，**外加两个诱饵** | `DASCTF{N3tw0rk_S3cur1ty_1s_1mp0rt4nt}` | 261 |
| 43 | [Misc · 宁波停车场位置推测（OSINT 定位）—— Writeup](06-Misc-OSINT与杂项/11-宁波停车场OSINT定位.md) | Misc / OSINT / 图像地理定位 | — | 133 |
| 44 | [message misc · NMEA 轨迹里的"消息"（未完成） — Writeup](06-Misc-OSINT与杂项/23-message-misc.md) | 111 MB 的假 GPS 日志：坐标被量化到「10 格 × 5 子档」的网格上，块结构清晰但语义未破 | — | 251 |

### Reverse（逆向）　`07-Reverse`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 45 | [第 9 题 · ezRe — Writeup](07-Reverse/09-ezRe.md) | 一个 **Python 3.9 的 .pyc**，里面是 RC4 + 两次编码；只能"读"，不能"跑" | `DASCTF{cb179cc6-c52b-4c17-9ef2-ac20cf8efdc3}` | 257 |
| 46 | [第 11 题 · Midre — Writeup](07-Reverse/11-Midre.md) | 输入先被 `"what's this"` 滚动 XOR，再进 AES-128-CBC 与 32 字节常量比对；靠 `call $+5 / ret` 制造反汇编错位来藏逻辑 | — | 255 |
| 47 | [第 12 题 · sm4rev — Writeup](07-Reverse/12-sm4rev.md) | 输入被 PKCS#7 补齐后用 SM4-ECB 加密，与 48 字节常量逐字节比对；密钥就摆在 checker 的 `movabs` 立即数里 | `DASCTF{SM4_is_secure_but_d0nt_t3ll_any0ne!}` | 235 |

### Pwn　`08-Pwn`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 48 | [pwn「栈溢出」— 逐字节读越界写，用 `0x3f` 跳过被自己压掉的 `idx`](08-Pwn/16-pwn-zhejiang2026-栈溢出.md) | `input()` 逐字节 `read` 且 `idx` 没有上界检查；写到 `buf+0x3c` 时正好压掉 `idx` 自己的低字节，送一个 `0x3f` 就把写指针顶到 `0x40`（saved rbp），于是能一路覆盖返回地址 | — | 260 |
| 49 | [pwn「one」— 1 字节堆溢出打 `__free_hook`（Ubuntu 18.04 / libc 2.27）](08-Pwn/17-pwn-one-libc227堆溢出.md) | `edit()` 比申请长度多读 1 字节，改掉邻居 chunk 的 size 做出重叠块，再把 `__free_hook` 写成 `system` | — | 241 |
| 50 | [shellcode — Writeup](08-Pwn/18-shellcode.md) | 只给你 10 个字节的 shellcode，还用 `memmem` 把 `0f 05` 堵死了，逼你换一条 syscall 指令 | — | 231 |
| 51 | [apple — Writeup](08-Pwn/19-apple.md) | 数组下标用**有符号** `jg` 做上界检查，于是负数下标把 `ptrs[]`/`sizes[]` 打通，一次 write 就变成任意写 | — | 254 |
| 52 | [muslexam — Writeup](08-Pwn/20-muslexam.md) | 菜单题故意送一个 puts 泄漏，真正的坑是 `edit` 从 `ptr-0x10` 开始写——在 musl 里这正好盖住 in-band slot 元数据 | — | 261 |

### 数据安全　`09-数据安全`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 53 | [数据安全 · 敏感信息提取 Writeup](09-数据安全/08-敏感信息提取.md) | 从自由文本里提取姓名 / 身份证 / 手机号 / IP，**边界断言**挡住"数字中间"的假匹配 | — | 171 |
| 54 | [数据安全 · 逐行分类 Writeup](09-数据安全/09-逐行分类.md) | 一行一个值、无标签，用 `re.fullmatch` 按顺序判定；顺序必须与输入一致 | — | 182 |
| 55 | [数据安全 · 脱敏打码 Writeup](09-数据安全/10-脱敏打码.md) | 先判类型、再按规则打码；**打码后长度必须和原值一致**（IP 除外） | — | 167 |
| 56 | [ds-enen — Writeup](09-数据安全/13-ds-enen.md) | 从固定 VHD 里按 FAT16 目录项把被删除的 `DATA.ZIP` 连续块捞出来，再用 EOCD 自校验；口令这一层没打通 | — | 261 |
| 57 | [ds-encode — Writeup](09-数据安全/14-ds-encode.md) | 规范只写在文档里、数据只活在页里：把「规则」和「数据」分别从 PDF 与 `.ibd` 里挖出来，再按规则算一遍 | — | 261 |

### AI 安全　`10-AI安全`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 58 | [猫娘提示词注入 · AI 安全 Writeup](10-AI安全/11-猫娘提示词注入.md) | system prompt 泄露、任务重构（把"泄露"包装成"翻译 + 格式化"） | `NSSCTF{9b8e7006-60a3-4e70-9e61-e5f511136929}` | 141 |

### 工具与速查　`11-工具与速查`

| # | 题目 | 一句话 / 考点 | 结果 | 行数 |
|---|---|---|---|---|
| 59 | [Wireshark 流量分析手册（CTF 杂项）](11-工具与速查/01-Wireshark流量分析手册.md) | — | `flag{e662ac154ca376e1c001ee8bbe81318b}` | 378 |
| 60 | [CTF Misc 常见文件类型与考点清单](11-工具与速查/02-Misc文件类型与考点清单.md) | 做法 / 工具 | — | 102 |
| 61 | [NSSCTF Misc 文件题型 × 真题解题链（题解调研笔记）](11-工具与速查/03-NSSCTF-Misc文件题型解题链.md) | — | — | 246 |
| 62 | [文件上传漏洞 · 做题笔记](11-工具与速查/04-文件上传漏洞做题笔记.md) | — | `NSSCTF{34374017-1f39-42bb-806b-3e7e77f830f5}` | 269 |
| 63 | [PHP 弱类型与 md5() 绕过 —— 做题笔记](11-工具与速查/05-PHP弱类型与md5绕过笔记.md) | — | `NSSCTF{...}` | 144 |
| 64 | [Wireshark 实战课：手把手复现 stolen.pcapng 分析](11-工具与速查/06-Wireshark实战-复现stolen分析.md) | — | `flag{xxxx}` | 203 |
| 65 | [词频分析工具包 · 目录索引](11-工具与速查/07-词频分析工具说明.md) | — | — | 144 |
| 66 | [或直接：''.join(c for c, _ in Counter(text).most_common())](11-工具与速查/08-词频分析变体手册.md) | — | `flag{%s}` | 200 |
| 67 | [正则库 · 换题目只改一行](11-工具与速查/09-词频分析正则库.md) | — | `flag{abc}` | 248 |
| 68 | [Python 补课 · 只补这道题用得到的](11-工具与速查/10-词频分析Python补课.md) | — | — | 302 |
| 69 | [拼图还原器 v1.0（Jigsaw Tile Reassembler）— 自建工具卡](11-工具与速查/11-拼图还原器.md) | 工具 | — | 76 |
| 70 | [ASCII 偏移小工具 v1.0 — 自建工具卡](11-工具与速查/12-AsciiShiftTool.md) | 工具 | — | 66 |
| 71 | [本地环境与赛场速查](11-工具与速查/13-本地环境与赛场速查.md) | 工具 | — | 75 |
| 72 | [外部笔记库与工具包索引（不重复造轮子）](11-工具与速查/14-外部笔记与工具包索引.md) | 工具 | — | 65 |

---

## 三、怎么用这本合集

**复习时**：先看每篇开头的结论块（flag / 一句话），再看「逐步复现」，原理段落只在想不通时读。

**比赛时**：按"拿到什么"查 `11-工具与速查/13-本地环境与赛场速查.md` 的对照表，直接跳到对应题型。

**赛后**：把新题按同样骨架加进对应目录，再跑一次索引脚本即可。

---

## 四、通用方法论（从这些题里抽出来的）

| 场景 | 第一步该做什么 | 不要做什么 |
|---|---|---|
| 网页只给一段代码 | 去掉 `highlight_file` 的 HTML 标签，还原成源码 | 不要盯着彩色标签看 |
| 代码要求"两个不同的值有相同哈希" | 先想"让函数返回 NULL"（数组），再想 `0e` | 不要去找真碰撞 |
| 有上传框 | 一次只改一个变量：后缀 → `Content-Type` → 文件头 | 不要同时改三个 |
| 上传成功但找不到 flag | 先 `phpinfo()` 看环境变量，再 `find /` | 不要只在自己传的目录里翻 |
| 页面回显"你的 IP 是 x.x.x.x" | 挨个试 10 个代理头（XFF / Client-IP / X-Real-IP…） | 不要只试 `X-Forwarded-For` 就放弃 |
| 流量包 | `统计 → 协议分级`，找"没有上层协议"的包 | 不要一上来就 Follow Stream |
| 流量里有压缩包/可执行文件 | `文件 → 导出对象 → HTTP/FTP`，按流落盘再逐个验魔数 | 不要手工抠字节 |
| PDF 打不开/要密码 | 扫 `/Encrypt`，看 `V/R/CFM` 判 RC4 还是 AES | 不要先修文件 |
| 图片看不出东西 | 先验魔数、补文件头、算 IHDR CRC、再看 IDAT 长度 | 不要一上来就跑 zsteg |
| 附件尾部有压缩包 | 先看里面内容格式对不对（是不是 uuencode / base64 套娃） | 不要看到 `flag` 就提交 |
| 一大堆碎片图片 | 数"纯色边"的碎片有几块，再谈像素对齐 | 不要只靠边缘代价（二维码会并列解） |
| RSA 给了同 n 两组 (e,c) | 先算 `gcd(e1,e2)`，=1 就是共模 | 不要先去分解 n |
| RSA 的 e 很小且 m 短 | 直接开 e 次方 | 不要套 Coppersmith |
| 流密码给了已知明文 | 异或拿 keystream，再看状态能否重放 | 不要试图恢复 key |
| 文本里全是 `{...}` | 抠内容 → 统计字频 → 降序拼接 | 不要一行行肉眼找 |
| 端口上不是 HTTP | 抓原始 banner，判断是 shell 还是二进制 | 不要硬套蚁剑/Web 工具 |

---

## 五、来源与说明

| 来源工作区 | 说明 |
|---|---|
| `D:\XiaoMibook\CTF学习` | 主力练习工作区：NSSCTF 靶场、Misc 文件题、流量分析、OSINT |
| `D:\DSH` | 图片隐写 / RSA / 数据安全 / AI 安全练习册 |
| `C:\Users\XiaoMibook\Documents\deepseek-harness\default-workspace\CTF-WP` | 省赛模拟题（DASCTF 赛制）成套 WP |
| 其他工作区（`D:\no-name`、`D:\逆向` 等） | 非 CTF 题目（游戏拓展逆向、学习通脚本），未收录 |

> **诚实标注**
> 1. 动态靶机（NSSCTF 容器）的 flag 会随重建变化，文中的 UUID 是当时那一次的值，方法不变。
> 2. 部分题目当时只做到 partial（未拿到最终 flag），文中已标注「未完成 / 卡点与正解方向」，不编造结果。
> 3. 少数题目只有文字记录、没有保留截图，正文用代码块呈现真实输出，未伪造图片。

*收录：题目 WP 58 篇 + 工具/速查 14 篇 = 72 篇。索引由脚本自动生成，新增题目后重跑即可。*