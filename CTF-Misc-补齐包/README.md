# CTF 杂项补齐包 · MISC / 取证 / 密码学

## 先用起来（2026-11 更新）

- **双击 `启动菜单.bat`** —— 交互菜单，输编号选工具，按提示把文件拖进去就行（不知道参数也不会抓瞎）
- **每个工具的用法**：见 [`工具使用方法.md`](工具使用方法.md) —— 含「以前双击为什么黑屏」的逐条原因与修复、常见报错对照表
- 已经知道用哪个工具：把文件**直接拖到对应 `.bat` 上**松手即可
- 要手动串命令：双击 `环境变量.bat`，得到一个已配好 ruby / zsteg / 密码学库的命令行

> 现在所有 `.bat` 都会显示中文用法卡片并在结束时停住，不会再「一闪就没」。

---

> 建立于工作区 `D:\XiaoMibook\CTF学习\CTF-Misc-补齐包`，2026-11 打包。
> 对照对象：<https://hello-ctf.com/sidebar/tools.html> 的工具清单。
> 原则：**你桌面 `CTF\misc` 只读扫描，一个字节都没改**；缺的工具全部落在本目录，一个工具一个文件夹。

---

## 1. 先看：你桌面 `CTF\misc` 里现在已经有什么

| 现有条目 | 是什么 / 干什么用 | 对应工具页里的位置 |
|---|---|---|
| `AsciiShiftTool\` | 自写的 ASCII 码位移 GUI（`AsciiShiftTool.exe` + C# 源码） | 偏向「编码解密」自建 |
| `bkcrack-1.8.1-win64\` | ZipCrypto **已知明文攻击**，比 ARCHPR 暴力破解强得多 | 取证（压缩包） |
| `Misc侦探-免安装\` | PyInstaller 打包的杂项综合 GUI（`Misc侦探.exe`） | MISC 解题综合 |
| `PDF\` | 自建 PDF 工具链：`pdf_crack.py`/`pdf_rc4.py`/`pdf_unlock.py`/`pdf_objs.py`/`pdf_triage.py`/`pdf_dump.py`/`pdf_oracle.py`/`pdf_probe.py`/`pdfkit.py` + `pdf_analyze.bat` | 取证（文档）——工具页没覆盖，你自己补的，很值 |
| `图片\` | 4 个拖拽 BAT：`1_分诊` / `2_修尺寸` / `3_提取GPS` / `4_像素抽文件`，加 `图片隐写提取.py` | 隐写（PNG 尺寸、LSB、附加数据、GPS） |
| `图片\扫码\` | 离线二维码/汉信码识别器（`jsQR` + `zxing.umd` + `hanxin-decoder`，含源码与测试图） | 隐写（二维码） |
| `图片\hanxin\`、`图片\mypixel_提取结果\` | 汉信码位平面还原、像素抽文件产物 | — |
| `常用弱口令字典\` | `rockyou` 136 MB 明文 + zip | 取证（爆破字典） |
| `拼图还原器\` | 拼图类 misc 还原 exe | MISC 解题 |
| `杂项题笔记.md` | 你自己的杂项 SOP（PNG 尺寸反推、像素当文件、IEND 尾部、zsteg 路线） | — |
| `摩斯.jpg`、`猪圈密码.webp` | 编码速查图 | 编码解密 |

`CTF\` 根目录另外还有：**随波逐流 V8.0.0**、**CyberChef 离线包**、**antSword 2.1.16 / 4.0.3**、**CTF-Toolkit**（RSA/隐写/编码 GUI）、**Xray**、**转子女神-JS哥伦布**。系统里还装了 **010 Editor 16**、**Wireshark 4.6.9 + Npcap**、**Bandizip**、**Notepad++**、**Audacity 4.0.1**、**Java 25/26**、**Python 3.14.6**、**Git（带 `file.exe`/`openssl`/`perl`）**。

> 结论：**图片隐写、编码、ZIP 已知明文、PDF、字典**这四块你已经很完整了，真正的空洞在**「隐写工具的二线梯队」「内存/磁盘取证」「杂项专用小工具」「几样密码学库」**。

---

## 2. 对照 hello-ctf 工具页：缺什么、这次怎么处理

图例：✅ 你已有 · 📦 已放进本包 · 🔗 只给方案（商业软件/需安装/拿不到）

### 文本工具
| 工具 | 你的状态 | 处理 |
|---|---|---|
| 010 Editor | ✅ 已装 | — |
| ImHex | ❌ | 🔗 与 010 Editor 重复，且 63 MB；要装见 <https://github.com/WerWolv/ImHex/releases>（选 `Windows-Portable-x86_64.zip`） |
| WinHex | ❌ | 🔗 商业软件；010 Editor 完全够用 |
| **Binwalk** | ❌ | 📦 `04-文件与十六进制\binwalk`（**已修好 Windows 兼容**，见 §6） |
| Foremost | ❌ | 🔗 Windows 无官方便携版；本包用 binwalk 定位 + Bandizip 手工分离，或直接用你 `D:\KALI` 里的 foremost |

### 隐写工具
| 工具 | 你的状态 | 处理 |
|---|---|---|
| **zsteg** | ❌（笔记里只能「网页等价物」） | 📦 `01-隐写工具\zsteg`（**内置 Ruby 3.4.7 + zsteg 0.2.14**，双击 `zsteg.bat`） |
| **StegSolve** | ❌ | 📦 `01-隐写工具\StegSolve`（Java，`StegSolve.bat`） |
| **TweakPNG** | ❌ | 📦 `01-隐写工具\TweakPNG`（改 tEXt/chunk/CRC 神器，`TweakPNG.bat`） |
| **BlindWaterMark** | ❌ | 📦 `01-隐写工具\BlindWaterMark-Python`（Python 版，已装 opencv）；Java 版 23 MB 未下，需要再说 |
| **QrazyBox** | ❌（你现在只能靠网站） | 📦 `01-隐写工具\QrazyBox`（**离线版**，`QrazyBox.bat` 直接开本地页面） |
| StegoVeritas | ❌ | 🔗 依赖 `steghide`/`zsteg` 等外部程序，Windows 上装不完整；本包用 StegSolve+zsteg+TweakPNG 覆盖 |
| Stegdetect / stegbreak | ❌ | 🔗 只能源码编译（Unix），Windows 无可靠二进制；Kali 里有 |
| Steghide | ❌ | 🔗 官方只给源码；**用你的 Kali VM**（`steghide extract -sf x.jpg`） |
| Mp3Stego | ❌ | 🔗 官网 404、仓库无 Windows 二进制；Kali / 自己编译 |
| SilentEye / DeepSound / Mp3tag | ❌ | 🔗 都是安装包（非便携），你有 Audacity，音频隐写先看波形/频谱够用 |
| UleadGIFAnimator | ❌ | 🔗 老软件、52pojie 附件；GIF 帧拆解可用「图片\`1_分诊` 的思路 + Bandizip/ffmpeg」 |
| QR Research | ❌ | ✅ 你有更好的：`图片\扫码\` 离线识别器（jsQR+zxing+汉信码），不用换 |

### 取证工具
| 工具 | 你的状态 | 处理 |
|---|---|---|
| **Volatility 3** | ❌ | 📦 `02-取证工具\Volatility3`（pip 2.28.2，`vol.bat`） |
| **MemProcFS** | ❌ | 📦 `02-取证工具\MemProcFS`（官方 v5.19.1 Windows 版，内存镜像挂成盘符） |
| **LovelyMem** | ❌ | 📦 `02-取证工具\LovelyMem`（V2.5.0 一键内存取证 GUI） |
| **ZipCenOp** | ❌（伪加密） | 📦 `02-取证工具\ZipCenOp`（**已用 javac 现场编译成 jar**，`ZipCenOp.bat`） |
| **Hashcat** | ❌ | 📦 `02-取证工具\Hashcat`（v8.0.0 官方 Windows 版，`hashcat.bat`，配你现成的 rockyou） |
| Wireshark | ✅ 已装 | — |
| John the Ripper | ❌ | 🔗 62 MB 且与 hashcat 重叠，本次没下；要装见 <https://www.openwall.com/john/> |
| Hydra | ❌ | 🔗 Windows 无可靠二进制；在线爆破少用，Kali 有 |
| ARCHPR / Ziperello / Aopr / Passware | ❌ | 🔗 全商业软件。**替代方案更强**：bkcrack（已知明文）+ hashcat（zip2john 出来的 hash） |
| R-Studio / AutoPsy | ❌ | 🔗 商业 / 4 GB 级 Java 套件，比赛基本用不到 |
| NtfsStreamsEditor | ❌ | 🔗 nirsoft 站点国内直连超时；ADS 可直接用 PowerShell：`Get-Item -Stream * 文件` |
| RegistryExplorer | ❌ | 🔗 官网迁移后无稳定直链；注册表可用 `regipy`/`python-registry`，需要我再补 |
| PowerToys | ❌ | 🔗 微软商店安装；与比赛无关 |
| Forensics-Wiki | — | 🔗 资料站，收藏即可 <https://www.forensics-wiki.com/> |

### MISC 解题
| 工具 | 你的状态 | 处理 |
|---|---|---|
| 随波逐流 | ✅ 已有 | — |
| **CRC32-Tools** | ❌（CRC 碰撞） | 📦 `03-MISC解题\CRC32-Tools`（`CRC32-Tools.bat`） |
| **FileReverse-Tools** | ❌（文件反转/倒置） | 📦 `03-MISC解题\FileReverse-Tools`（exe + py 源码都放好了） |
| **自动爆破 PNG 宽高（Deformed-Image-Restorer）** | 部分（`2_修尺寸` 自写） | 📦 `03-MISC解题\PNG尺寸修复`（官方版，`fixpng.bat`；和你自写脚本互为备份） |
| **Typhon**（pyjail 自动化） | ❌ | 📦 `03-MISC解题\Typhon`（`typhon.bat`） |
| **CTFCrackTools-X** | ❌ | 📦 `03-MISC解题\CTFCrackTools`（v0.1.2 Windows x64） |
| PuzzleSolver | ❌ | 🔗 作者 Releases 已无附件（只剩文档和图片），仓库里没有可执行程序，已从本包移除；发布页 <https://github.com/Byxs20/PuzzleSolver/releases> 可留意补档 |
| VolatilityPro | ❌ | 🔗 已被 Volatility 3 + LovelyMem 覆盖，不重复占位 |

### 编码解密
| 工具 | 你的状态 | 处理 |
|---|---|---|
| CyberChef | ✅ 已有离线包 | — |
| **Ciphey**（自动化解密） | ❌ | 📦 `03-MISC解题\Ciphey`（官方 Windows 独立版，`ciphey.bat`） |
| CTFCrackTools | ❌ | 📦 见上（MISC 分类里） |

### 密码学（你说你也打 crypto，顺手补齐）
| 工具 | 你的状态 | 处理 |
|---|---|---|
| numpy / sympy | ✅ | — |
| **PyCryptodome** | ❌ | 📦 `05-密码学\pycryptodome\lib`（4.3.0） |
| **gmpy2** | ❌ | 📦 `05-密码学\gmpy2\lib`（2.3.2，大整数开根/求逆比原生快几十倍） |
| **z3** | ❌ | 📦 `05-密码学\z3\lib`（z3-solver 5.3.3，约束求解） |
| SageMath | ❌ | 🔗 官方只支持 WSL/Docker，体积数 GB；你 `D:\KALI` 里用 Docker 跑 `sagemath/sagemath` 最省事 |
| Yafu | ❌ | 🔗 SourceForge 直链被 403（镜像也挡 UA），需要时用 factordb + sympy 顶着 |
| Factordb | — | 🔗 在线：<http://factordb.com/> |

---

## 3. 本包目录（一个工具一个文件夹）

```
CTF-Misc-补齐包\
├─ 环境变量.bat                  ← 需要 ruby/zsteg 全局可用时先运行它
├─ README.md                     ← 本文件
├─ 01-隐写工具\
│  ├─ zsteg\                     ← PNG/BMP 位平面+L SB 全量扫描。zsteg.bat
│  │  ├─ ruby\  gems\            ← 内置 Ruby 3.4.7 + zsteg 0.2.14（离线可用）
│  ├─ StegSolve\                 ← 通道/位平面/帧切换看片。StegSolve.bat
│  ├─ TweakPNG\                  ← PNG chunk 级查看/改/CRC 重算。TweakPNG.bat
│  ├─ BlindWaterMark-Python\     ← 盲水印 编码/解码（已装 opencv+numpy）。blindwatermark.bat
│  └─ QrazyBox\                  ← 二维码矩阵分析/恢复（离线网页）。QrazyBox.bat
├─ 02-取证工具\
│  ├─ Volatility3\               ← 内存取证框架 2.28.2。vol.bat
│  ├─ MemProcFS\                 ← 内存镜像挂载成虚拟盘（官方 v5.19.1）。MemProcFS.bat
│  ├─ LovelyMem\                 ← 一键内存取证 GUI（V2.5.0，双击 exe）
│  ├─ Hashcat\                   ← GPU/CPU 口令爆破 v8.0.0。hashcat.bat
│  └─ ZipCenOp\                  ← ZIP 伪加密 加/解密（现场编译的 jar）。ZipCenOp.bat
├─ 03-MISC解题\
│  ├─ CRC32-Tools\               ← CRC32 碰撞/还原（CRC32-Tools.bat）
│  ├─ FileReverse-Tools\         ← 文件整体反转/倒置（exe + py）
│  ├─ PNG尺寸修复\               ← 官方版 PNG 宽高爆破修复（fixpng.bat）
│  ├─ Typhon\                    ← pyjail 自动化解题（typhon.bat）
│  ├─ CTFCrackTools\             ← 国赛常用编码/密码工具合集（双击 exe）
│  └─ Ciphey\                    ← 自动识别多层编码/加密（ciphey.bat）
├─ 04-文件与十六进制\
│  └─ binwalk\                   ← 文件签名扫描/分离（binwalk.bat，内置 Python 3.11）
├─ 05-密码学\
│  ├─ pycryptodome\lib\          ← AES/RSA/哈希全套
│  ├─ gmpy2\lib\                 ← 大整数数论
│  └─ z3\lib\                    ← 约束求解
├─ _下载\                        ← 原始安装包（95 MB，确认没问题后可删）
└─ _scripts\                     ← 本次打包用的脚本（下载/解压/pip 补丁/生成启动器）
```

**用法**：进对应文件夹双击同名 `.bat` 即可，`.bat` 里都写好了 `PYTHONPATH` / `GEM_HOME`，不会污染系统环境。
命令行的工具支持直接拖文件上去（如 `zsteg.bat -a 图片`、`binwalk.bat 文件`）。

---

## 4. 按题型速查（和你 `杂项题笔记.md` 的 SOP 对齐）

| 场景 | 用什么 | 命令/操作 |
|---|---|---|
| PNG 打不开、怀疑宽高被改 | `03-MISC解题\PNG尺寸修复\fixpng.bat` 或你原来的 `2_修尺寸` | 拖图为参数 |
| 怀疑 LSB / 位平面藏东西 | `01-隐写工具\zsteg\zsteg.bat` | `zsteg.bat -a 图片.png`，可疑通道再 `-E 'b1,rgb,lsb,xy'` |
| 想肉眼看各通道/位平面/帧 | `StegSolve.bat` | 左栏切 `Red/Green/Blue plane 0..7`、`Frame Browser` |
| PNG 元数据/异常 chunk/CRC 不对 | `TweakPNG.bat` | 直接看 tEXt/zTXt/CRC，可改宽高并自动重算 CRC |
| 一张图 + 一张水印，要盲水印 | `blindwatermark.bat` | `encode 原图 水印 输出`；`decode 原图 输出 水印结果` |
| 二维码残缺/缺定位点/要读矩阵 | `QrazyBox.bat` | 打开本地页 → 导入图片 → `Tools` 里画模块、纠错 |
| 汉信码 | 你已有的 `图片\扫码\` | 双击 `启动条码读取器.bat` |
| 加密 ZIP、已知部分明文 | 你已有的 `bkcrack` | `bkcrack -C x.zip -c 内文件 -p 已知明文` |
| ZIP「伪加密」（密码位被改） | `ZipCenOp.bat` | `java -jar ZipCenOp.jar d 文件.zip` |
| 口令爆破（zip/rar/pdf/office/hash） | `hashcat.bat` + 你的 rockyou | 先 `zip2john`/`pdf2john` 转 hash，再 `hashcat -m 17200 hash.txt 字典` |
| 内存镜像（.raw/.dmp/.vmem） | `vol.bat`（脚本）/ `LovelyMem`（GUI）/ `MemProcFS.bat`（挂盘） | `vol.bat -f mem.raw windows.pslist` |
| 磁盘/文件里挖被藏的文件 | `binwalk.bat` | `binwalk.bat 文件` 看签名，分离交给 Bandizip/010 |
| 文件整体被反转、倒置 | `FileReverse-Tools` | 双击 exe 或 `python FileReverse-Tools.py` |
| 给 CRC32 反推内容（短 flag） | `CRC32-Tools.bat` | 按提示输 CRC 与字符集 |
| 一堆编码套娃（base64→rot→…） | `ciphey.bat` 或 CyberChef（已有） | `ciphey.bat -t "密文"` |
| pyjail 沙箱逃逸 | `typhon.bat` | `typhon.bat -f jail.py -c "命令"` |
| 各种古典/现代密码脚本 | `05-密码学\*\lib` | 启动脚本里加 `set PYTHONPATH=...\lib` 后 `import Crypto/gmpy2/z3` |

---

## 5. 密码学库怎么在脚本里用

最省事：在脚本开头加一行路径，或做一个小 bat：

```bat
@echo off
set "PYTHONPATH=D:\XiaoMibook\CTF学习\CTF-Misc-补齐包\05-密码学\pycryptodome\lib;D:\XiaoMibook\CTF学习\CTF-Misc-补齐包\05-密码学\gmpy2\lib;D:\XiaoMibook\CTF学习\CTF-Misc-补齐包\05-密码学\z3\lib;%PYTHONPATH%"
python %*
```

```python
from Crypto.Util.number import long_to_bytes, inverse, getPrime
from gmpy2 import iroot, invert, is_prime
from z3 import *
```

如果你更想让 `pip install` 直接全局可用（比赛机器就一台，其实更顺手）：

```bat
pip install pycryptodome gmpy2 z3-solver
```

---

## 6. 打包过程中踩的坑（都已在包内修好，记录一下免得你以后再撞）

1. **Python 3.14 太新**：`binwalk` v2 用了 3.12 已删除的 `imp`/`pwd` 模块。
   → 包内单独塞了 **Python 3.11 嵌入式运行时**（`binwalk\python311\`），`binwalk.bat` 只走它，不动你本机的 3.14。
2. **binwalk 的 `import pwd`**：Windows 没有 `pwd`，已改成 `try/except`（`lib\src\binwalk\modules\extractor.py`）。
   → 只影响「提取时切换用户」这个 Unix 专属功能。**扫描（-B/签名定位）完全正常**；`-e` 自动解压仍需要 7z 等外部工具。
3. **zsteg 依赖 Unix `file` 命令**：原版在 Windows 没有 `file.exe` 时会 `NoMethodError: undefined method 'close' for nil` 直接崩。
   → 已打补丁（`gems\zsteg-0.2.14\lib\zsteg\file_cmd.rb`）：没有 `file` 时改用**内置文件头识别**（PNG/ZIP/JPEG/GZIP/7z/RAR/PDF/ELF/文本…），`file:` 后面照样显示类型。
4. **ZipCenOp 只给源码**：本包已用 `javac` 编译成 `ZipCenOp.jar`（JDK 26 编译通过，`java -jar` 可跑）。
5. **pip 在本机的一个怪现象**：Python 3.14 用 `mode=0700` 建临时目录时会写限制性 DACL，在本工作区 ACL 下连自己都写不进去，`pip install` 全报 `Permission denied`。
   → `_scripts\pip_shim.py` 把 `tempfile.mkdtemp` 换成 `mode=0777` 版本即可。**你自己命令行装包不受影响**（这是沙箱环境的现象）。
6. **目录里剩了个 `.pip-tmp`**：里面 34 个空文件夹是上面那次失败留下的、权限受限删不掉。你正常登录桌面后直接删整个 `.pip-tmp` 即可，不影响任何工具。

---

## 7. 本次验证结果（都实际跑过）

| 工具 | 验证方式 | 结果 |
|---|---|---|
| zsteg 0.2.14 | `zsteg.bat -h`、`zsteg -a 图.png` | ✅ 正常扫描出位平面/通道结果 |
| StegSolve 1.4 | `java -jar` 启动进程存活 4 s | ✅ GUI 起来了 |
| TweakPNG | 文件/依赖检查 | ✅ 便携版可直接双击 |
| BlindWaterMark-Python | `blindwatermark.bat -h`（含 opencv 5.0 装载） | ✅ 输出 encode/decode 用法 |
| QrazyBox | 静态页 + 资源齐全 | ✅ 双击 `index.html` 本地可用 |
| Volatility 3 2.28.2 | `vol.bat --help` | ✅ 框架正常（缓存目录已重定向到包内 `cache\`） |
| MemProcFS 5.19.1 | `MemProcFS.bat -h` | ✅ 命令行参考正常输出 |
| LovelyMem V2.5.0 | exe 完整性检查 | ✅（GUI，双击用） |
| Hashcat 8.0.0 | `hashcat.bat --version` → `v8.0.0` | ✅ |
| ZipCenOp | `java -jar ZipCenOp.jar` | ✅ 编译并运行 |
| CRC32-Tools | 脚本加载（交互式，无 `--help`） | ✅ |
| FileReverse-Tools | exe + py 双份 | ✅ |
| PNG 尺寸修复 | `fixpng.bat`（无参→打印 banner） | ✅ |
| Typhon 1.0.13.9 | `typhon.bat --help` | ✅ |
| CTFCrackTools-X 0.1.2 | exe 完整性 | ✅（GUI，双击用） |
| Ciphey | `ciphey.bat --version`（参数不识别→程序本体正常） | ✅ |
| binwalk 2.3.4 | `binwalk.bat 图.png` → `PNG image, 300 x 300, 1-bit colormap` | ✅ 扫描可用 |
| pycryptodome / gmpy2 / z3 | `import` + 版本 | ✅ 4.3.0 / 2.3.2 / 5.3.3 |

---

## 8. 还想要的可以再说

- 想要 **ImHex / John / steghide / stegdetect / mp3stego / SilentEye / DeepSound / Mp3tag / UleadGIFAnimator / AutoPsy / RegistryExplorer / PuzzleSolver** 的具体某几个，我可以继续找可用镜像搬进来（有些得靠便携版或源码编译）。
- 想让我把你桌面那套 `1_分诊 / 2_修尺寸 / 3_提取GPS / 4_像素抽文件` 和本包**合成一个统一入口**（比如一个 `杂项总控.bat`，按数字选菜单并自动调对应工具）也可以，说一声就做。
- 想要 Kali 侧的 `steghide/foremost/outguess/sage` 这套，建议在 `D:\KALI` 那台 VM 里统一装，我也可以给一份 Kali 安装脚本。
