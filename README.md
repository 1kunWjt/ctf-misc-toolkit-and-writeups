# CTF 工具包 + Writeup 合集

> 两个目录：**CTF-Misc-补齐包**（Misc 方向工具与解题包）与 **CTF-WP合集**（自己做过的题的解题目录）。
> 全部离线可用，Typora / VS Code 直接打开 Markdown 即可。

## 目录

### 1. `CTF-Misc-补齐包/` — Misc 工具整合包

| 目录 | 内容 |
|---|---|
| `01-隐写工具` | 图片 / 音频隐写常用工具（含 BlindWaterMark、各类 LSB 工具） |
| `02-取证工具` | 内存取证、流量取证工具（LovelyMem 等） |
| `03-MISC解题` | 分诊脚本与解题模板 |
| `04-文件与十六进制` | binwalk、文件签名对照、十六进制工具 |
| `05-密码学` | z3、编码 / 古典密码工具 |
| `06-编码工具` | 随波逐流 CTF 编码工具 V8.0.0（走 [Release](https://github.com/1kunWjt/ctf-misc-toolkit-and-writeups/releases/tag/encoder-v8.0.0) 下载，见目录内说明） |
| `CyberChef-本地版` | CyberChef 离线版（断网可用，已修掉部分功能卡死问题） |
| `启动菜单.bat` / `_menu.ps1` | 一键菜单（按题型选工具） |
| `工具使用方法.md` | 每个工具干什么、怎么调 |

### 2. `CTF-WP合集/` — 自己做过的题的 Writeup

按方向分类，共 **58 篇题目 WP + 14 篇工具/速查**：

```
01-Web/              9 篇
02-Crypto/          14 篇
03-Misc-图片与隐写/    6 篇
04-Misc-流量分析/      8 篇
05-Misc-压缩包与文档/   3 篇
06-Misc-OSINT与杂项/   4 篇
07-Reverse/          3 篇
08-Pwn/              5 篇
09-数据安全/          5 篇
10-AI安全/            1 篇
11-工具与速查/        14 篇
```

从 [`CTF-WP合集/README.md`](CTF-WP合集/README.md) 进，里面有每题的一句话考点、flag 与完整索引。

## 使用

```text
# 只想找工具
CTF-Misc-补齐包\启动菜单.bat

# 只想看题解
CTF-WP合集\README.md   → Typora 打开，点表格里的题名
```

## 说明

- Writeup 里 **未解出的题如实标了「未完成 / 卡点与正解方向」**，没有编造 flag。
- 动态靶机（NSSCTF 等）的 flag 会随容器重建变化，文中的 UUID 是当时那一次的值，方法不变。
- 工具包内部分工具来自开源社区，版权归原作者；此处仅作个人备赛整合。
