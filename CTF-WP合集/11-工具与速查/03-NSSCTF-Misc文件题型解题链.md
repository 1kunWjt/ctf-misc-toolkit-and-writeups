# NSSCTF Misc 文件题型 × 真题解题链（题解调研笔记）

> 数据来源：NSSCTF 题库 `type=5`（共 1022 题）标签统计 + 站内题解（已登录核对）+ 公开 writeup（CSDN/博客园/腾讯云/GitHub，子代理交叉验证）。
> 题目链接格式：`https://www.nssctf.cn/problem/{id}`
>
> 文件类标签规模：流量分析 140 · 图片隐写 136 · 电子取证 67 · 编码分析 67 · 压缩包分析 45 · 二维码 41 · LSB 38 · 文档隐写 27 · 音视频隐写 26 · 伪加密 23 · 宽高修改 24 · 明文攻击 14 · PDF隐写 7 · word隐写 7 · xlsx 1

---

## 1. PNG / 图片类

### 真题解题链

**[3883] LitCTF 2023 这羽毛球怎么只有一半啊**（PNG 高度被改）
1. 010 Editor 打开 → IHDR chunk 报 CRC 校验错 → 宽高字段被动过
2. 经典 CRC32 爆破脚本：`binascii.crc32(IHDR_type + data)` 枚举 1~4000 匹配存储 CRC（宽度已知，只爆高度）
3. 010 里改回真实高度 → 完整图，flag 现形
- [CSDN](https://blog.csdn.net/m0_63613326/article/details/135436065)

**[1991] NISACTF 2022 为什么我什么都看不见**（坏 PNG + LSB）
1. 文件头只剩 `4E 47`（缺 `89 50`）→ 补全 `89 50 4E 47 0D 0A 1A 0A` 改后缀 .png
2. binwalk 可见内嵌 RAR，提出来没有 flag（**干扰项**）
3. 真考点 LSB：StegSolve → Analyse → Data Extract（或 `zsteg -a`）
- [CSDN](https://blog.csdn.net/2502_90869383/article/details/153780293)

**[2049] NISACTF 2022 huaji？**（jpg 尾藏加密 zip + EXIF 密码）
1. hex 里看到 `PK` 头和 flag.txt → foremost/binwalk 分离出 jpg + 加密 zip
2. 分离出的 jpg「属性→照相机型号」是一串十六进制 `6374665f4e4953415f32303232` → hex→ASCII 得密码 `ctf_NISA_2022`
- [博客园](https://www.cnblogs.com/magic123/articles/17466820.html)

**[401] SWPUCTF 2021 新生赛 gif好像有点大**（GIF 逐帧找二维码）
1. "大" = 800+ 帧；附加文件套路先排除
2. Stegsolve.jar Frame Browser 逐帧翻 → 第 562 帧是二维码；脚本法：PIL ImageSequence 分帧 + pyzbar 批量扫
- [CSDN](https://blog.csdn.net/QxQv4/article/details/141848442)

**[3881] LitCTF 2023 404notfound**（strings 换关键字）
1. binwalk 无果、010 搜 "flag" 无果（题眼 404）
2. 改搜 "ctf"/`{`/直接 `strings` → 明文 flag 藏在数据里
- 坑：**别只搜 flag 一个词**
- [CSDN](https://blog.csdn.net/2403_88493644/article/details/143441112)

### PNG 拿到手排查顺序
1. `file`/010 验魔数（缺头补头、假后缀改真身）
2. IHDR 宽高与画面不符 / 010 报 CRC 错 → **CRC32 爆破宽高**（"只有一半/破损"类）
3. `binwalk -e`、foremost、IEND 后尾部、hex 搜 PK/Rar!（**警惕假 flag 干扰包**）
4. `strings` + 010 多关键字（flag/ctf/{/NSS）
5. `exiftool` 元数据（型号/注释藏 hex 密码）
6. `zsteg -a`、StegSolve 位平面/Alpha/LSB、全黑图 PIL 拉对比度
7. tEXt/iTXt 异常块
8. 出图案 → 二维码缺定位角补角再扫；GIF/APNG 逐帧扫 + 帧时长隐写

---

## 2. ZIP / 压缩包类

### 站内已核实

**[507] 安徽省赛 2021 misc签到**（图包混合 + 属性密码）
- 站内题解一致：flag.png 其实是 **jpg**（头 `FF D8 FF E0`）→ 改后缀后 Windows 属性"备注"里有解压密码；同时 binwalk 尾部分离出加密 zip → 密码解压得 flag.png
- 考点链：魔数欺骗 → 文件属性备注/010 搜 `this is password` → 尾部分离 → 解压

**[47] SWPU 2020 套娃**（xlsx 三层套娃 + RC4）
1. 附件其实是 **xlsx（=zip）**：改后缀解压 → RC4data.txt + swpu.xlsx；再解 swpu.xlsx → esayrc4.xlsx + RC4key.zip
2. 010 拉到文件底部找 `password:6e4c…`（MD5 形）解开 RC4key.zip → RC4key.txt = `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
3. 对 RC4data.txt（`U2FsdGVkX1` 开头 = OpenSSL salted）做 RC4 解密得 flag
- 坑：密码藏在文件体末尾而不是 zip 注释
- [博客园](https://www.cnblogs.com/LEOGG321/p/14094598.html)

**[3882] LitCTF 2023 喜欢我的压缩包么**（题面给规格的纯数字爆破）
1. 010 看通用标志 0x06 与中央目录 0x1C 的 flag 位 → 排除伪加密，是真密码
2. 题面提示"6 位纯数字" → ARCHPR 纯数字模式（或 zip2john + john）→ 密码 `114514`
- 坑：**密码规格在题干里**，别去搞隐写

**[823] 广东强网杯 2021 个人决赛签到**（阴阳怪气编码）
- NSSCTF 复现版是未加密 zip，直接解开得 flag.txt；原考点是"富强民主文明和谐…"**社会主义核心价值观编码**解码（CyberChef/在线工具）
- 站内题解补充考点：伪加密 / strings / binwalk 尾部分离

**[693] BJDCTF 2020 签个到?**（.zip 实为 PNG）
1. "压缩包损坏" → 010/WinHex 看魔数是 `89 50 4E 47`
2. 改后缀 .png → 二维码 → 扫码得 flag
- 坑：以魔数为准，**别拿 `zip -FF` 修**

### ZIP 拿到手排查顺序
1. `file`/十六进制验魔数：可能是改名的 png/xlsx；尾部另挂包先 `binwalk -e`/foremost 分离；目录损坏才 `zip -FF`
2. 伪加密：010 对照通用头 0x06 与中央目录 0x1C 的 flag 位，不一致改 00（或 ZipCenOp）
3. 密码来源顺序：**题面提示（长度/字符集）→ 文件尾 strings → zip 注释 → 图片 EXIF/属性备注 → 内层明文**
4. 真密码：有规格用 ARCHPR/john；有未加密兄弟文件 + ZipCrypto → **bkcrack 已知明文攻击（≥12B）**
5. 解出仍无 flag：假 flag 干扰包、CRC32 碰撞/掩码爆破、010 搜注释区剩余字节
6. 套娃：产物还是 PK/7z/rar/xlsx 头就回第 1 步；提交前核对 NSSCTF{} 格式

---

## 3. 文档类（PDF / Word / Excel）

### PDF

**[465] 鹤城杯 2021 New MISC**（wbStego 隐写，站内 11 篇题解口径一致）
1. 多页俄文 PDF，肉眼无果；010 见 `09 20` 特征 → wbStego
2. **wbStego4.3open 选 Decode，空密码 Continue** → 解出内嵌文件即 flag
- 通用面先跑 pdfid/pdf-parser（/EmbeddedFile、/JS、/OpenAction）
- [博客园](https://www.cnblogs.com/srse/p/17751834.html)

**[3998] NSSRound#12 坏东西**（zip 套娃 → 损坏 PDF 不修！）
1. 首层 ARCHPR 爆破（密码=99020），随后发现**每层密码就是 zip 文件名** → python zipfile 递归批解
2. 最后 flag.pdf 打不开是故意的 → 记事本/010 读原始字节，flag 散在 `/Filter /FlateDecode` 流附近
- [博客园](https://www.cnblogs.com/start1/p/18600732)

### Word / docx

**[508] 领航杯江苏省赛 2021 签到题**（白色字体，⚠️不是零宽）
- 空行处有红色波浪下划线 → **Ctrl+A 全选改字体颜色为黑** → 显出 flag
- 零宽字符（U+200B/FEFF → 二进制还原）是另一类考点，遇到"完全看不出东西"才走
- [CSDN](https://blog.csdn.net/hhhhde_/article/details/159213989)

### Excel / xlsx

**[1386] GKCTF 2021 excel骚操作**（汉信码，站内题解已核实）
1. 单元格有值但被自定义格式 `;;;` 隐藏 → 全选改"G/通用格式" → 现出大量 1
2. **条件格式**把值=1 涂黑 + 行高调 27 → 呈现**汉信码**图案（中国 2D 条码）
3. "中国编码 APP"（或 toolsbug barcode-reader）解码得 flag
- [腾讯云](https://cloud.tencent.com/developer/article/2556397)

**[695] BJDCTF 2020 认真你就输了**（.xls 实为 xlsx 套壳）
1. 010 见 `PK` 头 → 改 .zip 解包出 xl/ 结构
2. 包内多出**非标准目录**（chars/）直接放 flag.txt → 送分，考点是"扩展名欺骗 + 别太认真"

**[1283] HBNIS 2019 Doc是什么鬼**（.doc 实为 zip/OOXML）
- hex 里没有 `D0CF 11 E0` → 改 .zip 解包 → 异样 Flag.xml 即 flag

### 文档类排查顺序
- **PDF**：pdfid/pdf-parser → pdftotext/strings → 打不开别急着修，先读原始字节 → binwalk/dd carving 内嵌 → 多 %%EOF 增量更新 → wbStego 专项 → qpdf --qdf
- **Word**：先验魔数（D0CF=老 doc 走 oletools/olevba；PK=docx 改 zip）→ 全选改字体颜色、显示编辑标记看修订 → document.xml 全文搜、零宽脚本 → docProps/media/页眉页脚
- **Excel**：改 zip 解包看 sharedStrings/隐藏 sheet/非标准文件 → 通用格式还原 `;;;` 隐藏值 → 条件格式涂黑+行高列宽还原码图 → 名称管理器/批注/嵌入对象

---

## 4. 音频 / 视频类

**[1072] MMACTF 2015 welcome**（wav 频谱 + 双轨）
1. 频谱图（Audacity 或 spectrum 脚本）得 5 位密码片段
2. 坑：双声道要**分开看频谱**；wavstego 的 `stools.py` 要改源码指定声道
3. 两段拼起来才是完整 flag
- [博客园](https://www.cnblogs.com/lijieyou/p/16203339.html)

**[39] SWPU 2019 神奇的二维码**（wav 频谱 QR + PNG 红通道 QR）
1. Audacity 频谱 → 残缺二维码，**补全定位点**后解码得密码（如 `nssctf{...}`）
2. Stegsolve 取 PNG **Red 0/1 平面** → 隐写二维码；**只取红通道**，别整图提 LSB
3. 密码开加密压缩包（部分 WP 用 foremost 分 zip），文件名拼接/压缩包内容收尾
- 坑：频谱图模糊可换 Spectrogram 窗口/重采样；两码独立、缺一不可

**[50] SWPU 2020 耗子尾汁**（gif 里藏 mp3+rar，多段链）
1. 附件是 2.9MB **gif**（不是 mp3！）：binwalk 分离失败就用 010 搜 `50 4B 01 02` / dd 抠尾部
2. 分离出 `find me.mp3` + 加密 `secret.rar`
3. mp3 拖 Audacity 看**波形**：语音后一段"滴答声" = 摩斯电码 → ASCII → hash → 在线 md5 反查得密码 `n1ce_try`
4. 解出 `19_20.txt`：文件名全是提示——`2^4/2^5/2^6` = base16/32/64 依次解，`19_20` = **仿射密码 a=19,b=20**
- [CTFHub 官方WP](https://writeup.ctfhub.com/Challenge/2020/SWPU-CTF-2020/Misc/91XmWXmBaB5D14aojzR2TM.html)

**[397] SWPUCTF 2021 新生赛 原来你也玩原神**（.zip 实为 mp3）
1. 文件头 `FF FB 92` = MPEG 帧 → 改后缀 mp3；频谱无异常排除频谱隐写
2. **MP3Stego**：`decode.exe xxx.mp3 -P ""`（空密码）→ 解出 PK 头的 txt
3. txt 改 .zip → 打不开 = **伪加密**：010 搜 `50 4B 01 02`，加密位 `09`→`00` → flag
- 考点组合：文件头识别 + MP3Stego + zip 伪加密
- [博客园 Anaxa](https://www.cnblogs.com/Anaxa/articles/18537240)

### 音频拿到手排查顺序
1. `file`/010 验真实文件头（zip 可能是 mp3，gif 里塞 mp3——见 397/50）
2. `binwalk` + `strings` + foremost/dd 查附加文件；分离出的中间产物按 ZIP 流程接处理
3. Audacity 三板斧：**频谱**（QR/文字）→ **波形**（滴答=摩斯、高低电平=01）→ 左右声道不对称
4. 按容器选工具：MP3→MP3Stego，WAV→stools/wavstego/SilentEye，APE→专用修复，语音杂音先看图再试 SSTV(Robot36)
5. 拨号音 = DTMF：dtmf2num + 手机九键（代表题 [WUSTCTF2020]girlfriend，不是 id 35）
6. 收尾链：base64→base32→base16→仿射/凯撒→md5 反查，一层层脱

> ⚠️ **id 35 [SWPU 2019]Network 勘误**：站内标签有"电话音"但实际**不是音频题**。附件是一个 txt，一行一个 TTL 值：
> 只有 `63/127/191/255` → **TTL 低 2bit 隐写**，映射 `00/01/10/11` 拼比特流转字符 → 得十六进制串 → unhexlify 出 `ans.zip` → 伪加密（09→00）→ 里面是 **base64 套娃** while 循环解到 `{`。
> 归属"流量/编码"类才对。来源：[博客园](https://www.cnblogs.com/darling024/p/15502119.html)

---

## 5. 取证 / 流量类（见另一笔记）

你已有 [Wireshark流量分析手册](笔记/Wireshark流量分析手册.md) 和 stolen writeup，对应站内大标签：流量分析 140 / 电子取证 67 / 内存取证 46（Volatility3）/ 日志审计 37（陇剑杯系列，站内你正打开的 290/292 就是）。

---

## 6. 进阶 20 题计划（与前面 21 题零重叠，每题一个不同的解法）

### 图片隐写类（8 题）
| # | 题目 | 代表解法（不与已刷重复） |
|---|---|---|
| 1 | [318] 第五空间 2021 alpha10 | **盲水印**：DFT/FFT 频域提取（盲水印 python 脚本），不是空间域 LSB |
| 2 | [3680] GDOUCTF 2023 pixelart | **像素二值化重绘**：读 RGB 最低位矩阵重画成图（PIL 脚本） |
| 3 | [2321] SCTF 2014 misc400 | **IDAT stego**：PNG 压缩数据流重排序隐写，用 idat_stego 工具解 |
| 4 | [2361] SDCTF 2022 Ishihara test++ | **SVG 源码隐写**：色盲测试图真身是 svg，看源码/图层 |
| 5 | [1865] HGAME 2022 谁不喜欢猫猫呢 | **Arnold 猫地图还原 + piet 语言**：图像置乱复原后当程序执行 |
| 6 | [3274] ACTF 2022 Broken QRCode | **二维码结构修复**：补定位点/校正格后解码（比 401 的逐帧更硬核） |
| 7 | [1982] WUSTCTF 2020 alison_likes_jojo | **Outguess 算法隐写**（区别于 zsteg/Steghide 家族） |
| 8 | [843] CISCN 2021 running_pixel | **GIF 帧间差分→01 字符**（401 是找单帧二维码，这题是逐帧建矩阵） |

### 压缩包类（6 题）
| # | 题目 | 代表解法 |
|---|---|---|
| 9 | [6535] GHCTF 2025 mybrave | **bkcrack 已知明文攻击**（通解里讲了两次还没实操的就是它） |
| 10 | [3305] MoeCTF 2022 cccrrc | **CRC32 碰撞**：短文件名给 CRC，脚本爆明文 |
| 11 | [1091] GXYCTF 2019 佛系青年 | **zip 伪加密修复 + 与佛论禅编码**双连 |
| 12 | [400] SWPUCTF 2021 zipbomb | **解压炸弹识别**：套壳嵌套/解压比结构知识 |
| 13 | [395] SWPUCTF 2021 我的银行卡密码 | **键盘密码**推压缩包密码（密码来源新姿势） |
| 14 | [92] CISCN 2018 Picture | **base64↔图片链式还原** + 包结构 |

### 文档隐写类（6 题）
| # | 题目 | 代表解法 |
|---|---|---|
| 15 | [213] UTCTF 2020 Zero | **零宽字符**（U+200B 系 → 二进制；508 勘误后这条线补上） |
| 16 | [4484] FSCTF 2023 行不行啊细狗 | **docx OOXML 深层结构**：document.xml 里修订/隐藏段 |
| 17 | [2518] 长城杯 2022 办公室爱情 | **自定义符号字体（Wingdings）→ 01 还原** |
| 18 | [5926] SWPUCTF 2024 逆天方式ADS | **NTFS 交替数据流 ADS**：`dir /r` + streams 提取 |
| 19 | [2631] SWPUCTF 2022 Coffee Please | **Office 打开密码哈希**：office2john + john（真·加密文档） |
| 20 | [4601] FSCTF 2023 最终试炼hhh | **PDF×压缩包组合拳**：伪加密与 PDF 隐写串联收尾 |

> 注：解法概括按站内标签 + 公开题解惯例给出，个别冷门题（4/12/14）以实际附件为准，做的时候先 `file` 定身再按图施工。

## 7. 考法补位 12 题（20 题清单之外的剩余考法）

| 缺口考法 | 补位题 | 备注 |
|---|---|---|
| Steghide 工具隐写 | [458] 鹤城杯 Misc2 | solved 939；LSB+口令 |
| Steghide 口令爆破 | [3964] LitCTF ssvvgg | base64转图片+爆破 |
| SilentEye 向导隐写 | [905] 安洵杯 BeCare4 | 混零宽字符 |
| EZStego | [7115] GCCCTF 2025 ezmisc | 站内有官方题解 |
| 通道分离/红蓝合成（色盲图） | [694] BJD 藏藏藏 | 图片分离标签主玩法 |
| 光栅透明片叠加 | [875] GFCTF 重生之我在A国当间谍 | 光栅+汉信码双考 |
| PNG IDAT 数据重建 | [3884] LitCTF 破损的图片 / [4599] FSCTF 萧河 | 比补文件头更深 |
| GIF 帧时间/间隔隐写 | [5814] SWPU 它好可爱啊 / [7282] 玄武杯 盯帧 | 读时间不读帧图 |
| ZIP 注释区/extra field 结构隐写 | [854] HITCTF zip / [6885] Zoinked Zip 1 / [6368] 陇剑杯 ez_web(三) | ZIP 字段本身当考点 |
| 掩码攻击（已知部分口令） | [3313] MoeCTF zip套娃 | 伪加密+爆破+掩码 |
| PDF417 长条码 | [3380] MoeCTF 2021 White Album | 二维码之外的码 |
| Word 修订/批注 + Office 组合 | [2144] 办公文件里的秘密 | 压缩包×文档 |
| PDF 书签/附件面板/增量更新 | [2657] Cover Removed / [920] justCTF pdf / [4241] Stupid students | 多 %%EOF 结构 |

> **空白说明**：三大类标签内无纯 VBA 宏题；老式 OLE `.doc/.xls` olevba 考点在「office文档破解」「电子取证」标签（如 [2455] 蓝帽杯 计算机取证_3）。

## 附：本次调研方法备忘（下次不靠工具手动即可）
- 题目列表 API：`POST https://www.nssctf.cn/api/problem/v3/list/{页}/{每页数}/`，body `{"type":5}`（1=Misc…），返回带标签/解题数
- 题目详情：`GET /api/problem/v2/{id}/`（annex 字段=是否有附件）
- 题解需登录态在浏览器里看：`https://www.nssctf.cn/problem/{id}/writeups`
- 站内题解 API（`/api/problem/{id}/wp/official/` 等）匿名访问返回 `{"code":402}`
