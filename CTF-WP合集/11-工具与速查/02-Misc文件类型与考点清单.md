# CTF Misc 常见文件类型与考点清单

> 用途：拿到附件第一步先认类型（`file xxx` / 看魔数），再按下面的考点排查。
> 已刷到：pdf、zip、png、xlsx —— 都在下表里。

## 0. 通用起手式（任何文件先做三件事）
1. `file` / 十六进制头 看真实类型（魔数和扩展名不符 → 改后缀再处理）
2. `strings` 扫明文（flag、密码、提示经常直接躺在里面）
3. `binwalk` + `exiftool`（尾部附加数据、元数据注释）

## 1. 压缩包类（zip / rar / 7z / tar / gz）
| 考点 | 做法 / 工具 |
|---|---|
| 伪加密 | 对比 flag 位与压缩方法，010 Editor 模板 / `zip -FF`，改全局和局部文件头加密位 |
| 真加密（ZipCrypto） | **已知明文攻击 bkcrack**（别上来就爆密码），有未加密兄弟文件就行 |
| 真加密（AES/7z/rar5） | hashcat/john + 字典；密码线索常在文件名、备注、题目正文 |
| ZIP 注释加密 | 压缩格式选 ZIP 才能加密"注释"，注释里就是 flag（右键查看注释） |
| CRC32 碰撞 | 文件极短（≤32 字节）+ 给了 CRC，写脚本碰撞出明文（cyberchef CRC32 工具/脚本） |
| 套娃/分卷 | 解压后递归再解；`tar.gz` 多层；zip 里 zip |
| 损坏包 | `zip -FF` / `7z t` 修复；ARJ、cab 用对应工具 |
| 文件名隐写 | 零宽字符文件名、`.\` 目录名、批量文件内容按序拼接（你的 jigsaw 拼图脚本就是这个思路） |

## 2. 图片类（png / jpg / bmp / gif / webp / tiff / ico）
| 考点 | 做法 / 工具 |
|---|---|
| 元数据 | `exiftool`（GPS、Make、注释、Software 字段） |
| 尾部附加 | `binwalk -e`；jpg/png 后拖 zip、rar、txt |
| PNG 块隐写 | `zsteg -a file.png`（LSB、alpha、palette、tRNS、jsteg 一站式）；checkpng / pngcheck |
| LSB 隐写 | Stegsolve 逐平面 / Silent Eye（jpg/bmp）/ outguess |
| steghide | `steghide extract -sf xxx -p 密码`（jpg/bmp 常见，密码另找） |
| 二维码 | 残缺 QR 补全（QQ 修复）、半透明 QR（调亮度）、彩色 QR 分通道、多 QR 叠加（QR 扫码后比对）、二维码+容错率截图 |
| 颜色通道 | 红蓝分离（Stegsolve Color 通道）、调色板隐藏、像素二值化转 0/1 文本 |
| 像素/透明 | 全黑图但 alpha 有内容；把像素当数据（宽高→01 矩阵） |
| 帧隐写 | gif/apng 逐帧拆（`convert -coalesce`），帧里藏字或拼图 |
| 损坏图片 | 重绘 IDAT、修 CRC、`pngrepair`；jpg 缺 FFFF D8 头等 |

## 3. 文档类（重点：你刷到的 pdf / xlsx）
### PDF
- `pdftotext` / `strings`：文本层直接有 flag（白字隐形文本很常见）
- `pdfid` / `peepdf` / `pdf-parser`：结构分析
- **附件隐写**：PDF 可内嵌文件（`pdf_extractor -x` 或 010 模板 / Foxit 看附件面板）
- 尾部拖数据：binwalk
- 图片型 PDF：导出内嵌图（`pdfimages`）再走图片隐写套路
- 书签/链接/注释/版本差异（PDF 1.x 增量更新：旧版本内容藏在后面）

### xlsx / xls / docx / pptx
- **xlsx/docx/pptx = zip**：改后缀解压，看 `sharedStrings.xml`（文本全在这）、`worksheets`、`comments*.xml`（单元格批注）、`drawings`（内嵌图）、`vbaProject.bin`
- Excel 考点：隐藏工作表/隐藏行列/隐藏列宽、**工作表保护**（删 `<sheetProtection>` 即可编辑）、筛选漏掉的行、单元格批注、**定义的名称**（公式→名称管理里有 flag）、条件格式、空单元格内容
- 老 `.xls/.doc`（OLE 二进制）：`olevba`（oletools）抽 VBA 宏源码、`strings`
- 带宏 `.xlsm`：宏代码里是密文/逻辑
- 密码保护：xlsx 的加密 → `office2john` + john

### 其他文档
- epub/mobi：改 zip 解 / calibre 转换
- chm：反编译（7z 可解）
- 记事本 .txt：各种编码套娃见 §5

## 4. 音频 / 视频类
| 格式 | 考点 |
|---|---|
| wav | **频谱图**（Audacity/Spectrogram 看 QR/文字）、LSB（stools/wavstego）、DTMF 电话键音（图灵工坊/dtmf 解码）、波形高低电平转 01 |
| mp3 | 注释帧 ID3、binwalk 尾部、频谱 |
| flac | 元数据注释 |
| mp4/avi | box 结构、binwalk、逐帧、**字幕轨**（软字幕 .ass/.srt 里藏字） |

## 5. 纯文本 / 编码类（无后缀或 .txt）
- Base 家族：Base64/32/16/58/85、摩斯码（`.-..` / `--·` 变形）、URL、Unicode `\uXXXX`、HTML 实体、Quoted-printable、 bacon、猪圈码
- 语言型：Brainfuck、Ook!、JSFuck、草蟒文、shit encode
- 变形：多表替换、01 串、字母位置、键盘码、电报码、ASCII 错位（你写过 AsciiShiftTool）
- 判定顺序：`Base 套娃识别` 用 CyberChef "From Base64" 链 + Magic 自动识别

## 6. 流量 / 取证类（你已经有一摊笔记）
- pcap/pcapng：Wireshark（HTTP 对象流、TCP 流重组、文件传输导出、802.11 握手、USB 键鼠/鼠标轨迹）
- 内存 dump（raw/vmem/lime）：Volatility3（进程、命令行、截图、字符串）
- 磁盘镜像 img/vhd/E01：Autopsy / FTK / 挂载 + 文件 carving（photorec）
- evtx / 注册表 / .bash_history / $MFT / 回收站 $Recycle.Bin：恢复类
- .git.zip / .svn：源码泄漏，`GitHack`
- KeePass `.kdbx`：keepass2john + john

## 7. 二进制/容器伪装类
- 扩展名不认识：`file` + 010 查头 → 常是 zip/7z/ELF 改名
- sqlite `.db/.sqlite`：sqlite3 打开、`.tables` 导出
- `.pem/.pub/.key`：crypto 乱入 misc（RSA 题），openssl 解析
- `.hc` 词表、`.hash` 文件：john/hashcat
- Docker 镜像 tar：分层解出文件

## 8. 冷门但考过的
- 井字棋/数独/扫雷存档（`.minesweeper`）、五子棋棋谱
- Minecraft 存档（region 文件 NBT）
- Android `shared_prefs` / `.db` 导出
- Windows 桌面 `Thumbs.db`、`.DS_Store`（目录名泄漏）
- 截图拼接/打码图片复原（你做过）
- 鼠标/键盘 USB  pcap 还原轨迹与击键

## 速记：拿到文件的判断链
```
file 认类型 → strings 扫明文 → exiftool 看元数据 → binwalk 看附加
→ 是 zip 就解(zip 家族含 xlsx/docx) → 是图就 zsteg/steghide/Stegsolve
→ 是 pdf 就 pdfid/pdftotext/抽附件 → 是音频就频谱
→ 还不行就回题目正文找密码/提示
```
