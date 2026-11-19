# 06 · 编码工具（Encoding Tools）

> 这一层专放"把东西换来换去"的工具：Base 家族、古典密码、现代编码、哈希、进制转换。

## 目录内容

| 工具 | 形态 | 位置 | 说明 |
|---|---|---|---|
| 随波逐流 CTF 编码工具 V8.0.0 | 单文件 exe（176 MB） | **Release 下载** → [`encoder-v8.0.0`](https://github.com/1kunWjt/ctf-misc-toolkit-and-writeups/releases/tag/encoder-v8.0.0) | 一键穷举常见编码/古典密码，解不开就"全部试一遍" |
| CyberChef 本地版 | 离线 HTML 应用 | [`../CyberChef-本地版/`](../CyberChef-本地版/) | 断网可用；Recipe 可存可分享 |

## 为什么随波逐流放在 Release 而不是这个目录里

GitHub **单文件上限 100 MB**（硬限制，非建议值）。这个工具解包后有 **176 MB**：

```
[随波逐流]CTF编码工具_V8.0.0_Release_20261018.rar   172.9 MB
  └─ [随波逐流]CTF编码工具_V8.0.0_Release_20261018.exe  176.08 MB
```

放进仓库会被 `remote: error: File ... is 176.08 MB; this exceeds GitHub's file size limit of 100.00 MB` 直接拒收。
所以原始附件挂在 **Release 资产**上（Release 单文件上限 2 GB），仓库里只留这份说明。

## 下载与校验

- 下载页：<https://github.com/1kunWjt/ctf-misc-toolkit-and-writeups/releases/tag/encoder-v8.0.0>
- 文件名：`[随波逐流]CTF编码工具_V8.0.0_Release_20261018.rar`
- 大小：172,902,xxx 字节（172.9 MB）
- SHA-256：

```
F928D0CBF684C0BAB8537A5C2EE2444D421BC4239714414AE37D9695F75C568A
```

校验命令（Windows PowerShell）：

```powershell
Get-FileHash -LiteralPath '.\随波逐流CTF编码工具_V8.0.0.rar' -Algorithm SHA256
```

## 怎么用（30 秒）

1. 下载 `.rar` → 解压得到单个 `.exe`（绿色版，免安装）
2. 双击运行
3. 把题目给的密文粘进输入框 → 点"一键解码"/"全部尝试"
4. 结果列表里按"可读性"排序，找像 flag 的那条
5. 解不出就换参数（字符集、进制、是否 URL 编码过）再试

典型适用题型：

```
一串 Base64 看不出东西     -> 先 Base64 解一层，再丢进来
怀疑是古典密码            -> 直接选"古典密码"批量试（凯撒/栅栏/维吉尼亚/培根…）
怀疑多层套娃              -> "自动多层解码"
怀疑进制转换              -> 二进制/八进制/十六进制一键转
怀疑哈希                  -> 只做识别，不做爆破（爆破用 hashcat）
```

## 注意

- 这是**第三方工具**，版权归"随波逐流"作者；此处仅作个人备赛留存。
- 176 MB 的 exe 首次启动稍慢，属正常。
- 报毒误报较常见（加壳/单文件打包），介意就在沙箱/虚拟机里跑。
