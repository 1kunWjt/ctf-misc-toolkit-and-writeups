# [CISCN 2018] Picture —— 图片尾部 zlib → base64 → Zip → uuencode 四层 Writeup

> 题目：一张 Uncle Sam 表情包（"I WANT YOU TO SHOW ME YOUR CODE"），要求找 flag
> 分类：Misc / 图片隐写（实为**容器追加数据**，不是像素隐写）
> 附件：`Picture.jpg`，491×651，39271 字节
> sha256：`4a29b93d38dccba0b8d2c1a27b5ac786b2a0157be9fc387f8bd630ec7dc685d5`

## 〇、flag

```
CISCN{2388AF2893EB85EB1B439ABFF617319F}
```

## 一、先判方向：这题不是"改像素"的隐写

拿到图片的习惯动作是 stegsolve / LSB / steghide / binwalk 一把梭。这题前三种全部空手：

| 检查项 | 结果 |
|---|---|
| `PIL` 尺寸/模式 | 491×651 RGB，标准 JFIF（density 1×1，无 EXIF、无缩略图） |
| JPEG 标记链 | 仅 `SOI → APP0 → DQT×2 → SOF0 → DHT×4 → SOS → EOI`，**没有第二个 SOI**，没有 APPn 注释段 |
| LSB（R/G/B、行序/列序） | LSB 均值 0.62~0.67（偏高是白底大图正常值），提取体全无可打印串、无 `PK`/`flag` 魔数 |
| 文件头尾一致性 | 正常 `FF D8 FF E0` 开头，**但 EOI 之后还有 387 字节** |

**判据只有一条：`FF D9` 不是文件末尾。** 真实结构是"合法 JPEG + 追加载荷"，追加数据在偏移 38882 之后。

```powershell
# 找最后一个 EOI
$b=[System.IO.File]::ReadAllBytes("Picture.jpg"); $b.Length      # 39271
# EOI@38882 → 尾部 387 字节，前两字节 78 9C = zlib
```

## 二、第一层：EOI 之后是 zlib 流

尾部 387 字节以 `78 9C` 开头，是标准的 zlib 压缩流（且是**完整的**，`zlib.decompress` 一次成功，`unused_data` 为空、`eof=True`，没有第二段隐藏数据）。

```python
import zlib
trail = open("Picture.jpg","rb").read()[38884:]   # EOI(2字节) 之后
s1 = zlib.decompress(trail)                        # 387 B → 604 B
print(s1[:24])   # b'S1ADBBQAAQAAADkwl0xs4x98'    ← 一眼 base64
```

解压出来是 604 字节的纯 base64 文本。**注意：这里不是直接改后缀就能开的东西，先做编码识别。**

## 三、第二层：base64 → ZIP，但魔数被换掉了

```python
import binascii
s2 = bytearray(binascii.a2b_base64(s1))    # 604 B → 452 B
print(s2[:4].hex())                        # 4b 50 03 04
```

正常 ZIP 本地文件头是 `50 4B 03 04`（`PK\x03\x04`）。这里拿到的是 `4B 50`——**P 和 K 两个字节被对调了**，于是：

- `file` 认不出（报 data）
- `unzip` 报 "cannot find zipfile directory"
- `binwalk` 也不一定能自动修

但**其余结构全部完好**：CRC、central directory、EOCD 偏移自洽，说明只动了开头 2 字节。把 `4B 50` 改回 `50 4B` 就得到合法压缩包：

```python
s2[0:2] = b"PK"
open("fixed.zip","wb").write(s2)
```

```python
import zipfile
zf = zipfile.ZipFile("fixed.zip")
info = zf.infolist()[0]
print(info.filename, hex(info.flag_bits), info.compress_type, info.file_size, info.compress_size)
# code 0x1 0 78 90      ← flag_bits=1 表示 ZipCrypto 加密；method=0 存储；78 B 明文；90 B 密文(=12 字节加密头+78)
```

细节：90 = 12 + 78 正好对上 ZipCrypto 的 12 字节加密头，所以**加密是真的**，不是只改了个标志位。

## 四、第三层：注释里的"假 IDLE 会话"就是密码提示

压缩包 220 字节的 comment 是一段伪造的 Python 2.7 IDLE 会话（`data` 字节按 **Big5** 解才通顺，`A8 7D` = "良"）：

```
[Python 2.7]
>>> 良良良

Traceback (most recent call last):
  File "<pyshell#0>", line 1, in <module>
    良良良
ZeroDivisionError: 良良良…良   <- password ;)
>>> 
```

看懂这段话的关键不是数"良"的个数，而是认出**这是一段被挖空的 Python 零除报错**：

- `>>> 良良良` = 用户输入被替换（长度 3，正好对应 `1/0` 这种三字符表达式）
- `ZeroDivisionError: 良…` = 报错正文被替换
- `<- password ;)` = 被替换掉的**报错正文本身**就是密码

Python 2.7 里整数零除的报错正文是：

```python
>>> 1/0
ZeroDivisionError: integer division or modulo by zero
```

所以密码 = `integer division or modulo by zero`（34 字符）。

> 坑：注释里"良"只有 30 个，而真实文案 34 字符——**数量对不上**，所以别去猜"密码长度 30"。这个占位符只是打码，不是长度提示。
> 另一个坑：要的是 Python 2.7 的 `integer division or modulo by zero`（34 字符），不是 Python 3 的 `division by zero`；版本写错会一直解不开。

```python
data = zf.read("code", pwd=b"integer division or modulo by zero")
# b'begin 644 key.txt\nG0TE30TY[,C,X.$%&,C@Y,T5".#5%0B%"-#,Y04)&1C8Q-S,Q.49]\n`\nend\n'
```

## 五、第四层：uuencode 收尾

解出来的 78 字节内容不是 flag，而是一段 **uuencode**：

```
begin 644 key.txt
G0TE30TY[,C,X.$%&,C@Y,T5".#5%0B%"-#,Y04)&1C8Q-S,Q.49]
`
end
```

识别特征：`begin <mode> <filename>` … `end`，中间每行首字符是"本行字节数+32"（这里是 `G` = 0x47-0x20 = 39），行尾的 `` ` `` 是零长度行。用 `binascii.a2b_uu` 解：

```python
import binascii
lines = data.decode().splitlines()
out = b"".join(binascii.a2b_uu(l.encode()) for l in lines[1:-1] if l.strip() not in ("`", ""))
print(out)     # b'CISCN{2388AF2893EB85EB1B439ABFF617319F}'
```

## 六、完整链路

| # | 载体/动作 | 关键特征 | 结果 |
|---|---|---|---|
| 0 | `Picture.jpg` | 合法 JPEG，但 `FF D9` @38882 后仍有 387 B | 定位追加载荷 |
| 1 | zlib 解压 | `78 9C`，流完整、无剩余字节 | 604 B base64 文本 |
| 2 | base64 解码 | 头 `4B 50 03 04`（PK 被对调） | 452 B ZIP（改名无用，需修魔数） |
| 3 | 修 `4B 50 → 50 4B` | CRC/中央目录/EOCD 全部自洽 | 合法 ZIP，条目 `code`，ZipCrypto |
| 4 | 读注释 | 伪造 IDLE 会话 + `<- password ;)` | 密码 = Python 2.7 零除报错正文 |
| 5 | ZipCrypto 解密 | CRC 校验通过，78 B | uuencode 文本 |
| 6 | uuencode 解码 | `begin 644 key.txt` / `end` | **flag** |

## 七、踩坑清单

1. **只做像素隐写**：LSB / stegsolve 一条路走到黑，忘了看文件尾。抓图先跑"最后一个 EOI 之后是否还有数据"。
2. **`unzip` 报错就放弃**：魔数被换是"格式理解题"，`xxd` 看前 16 字节即可判断，修 2 个字节就活。
3. **把提示当密码本体**：注释里"良"是占位符；密码是它替换掉的**标准报错文案**，还要注意 Python 2.7 与 3.x 文案不同。
4. **密码里有空格**：`integer division or modulo by zero` 中间是单个半角空格，手输容易多一个空格。
5. **最后一层漏解**：解出 `begin 644` 不是终点，uuencode 还要再解一次。
6. **干扰项**：DOS 时间戳 `0x3039` 恰好等于十进制 12345（"经典弱密码"），日期 2018-04-23 06:01:50 也像密码——都是**假线索**，别陷进去。

## 八、复现

```bash
# 一条命令从原图跑到 flag（脚本内含各阶段 hex 校验与断言）
python solve.py
```

关键代码骨架（完整版见 `ciscn2018_picture/solve.py`）：

```python
raw = open("Picture.jpg","rb").read()
eoi = raw.rfind(b'\xff\xd9')
s1  = zlib.decompress(raw[eoi+2:])              # 1
s2  = bytearray(binascii.a2b_base64(s1)); s2[0:2] = b"PK"   # 2 + 修魔数
zf  = zipfile.ZipFile(io.BytesIO(bytes(s2)))
s3  = zf.read("code", pwd=b"integer division or modulo by zero")   # 3
s4  = b"".join(binascii.a2b_uu(l.encode()) for l in s3.decode().splitlines()[1:-1]
               if l.strip() not in ("`", ""))                  # 4
print(s4.decode())                              # CISCN{...}
```

## 九、知识点小结

| 知识点 | 要点 |
|---|---|
| JPEG 追加数据 | 解析器遇 `FF D9` 即停，后面随便加；检测=比较"最后一个 EOI 偏移"与文件长度 |
| zlib 识别 | `78 01/5E/9C/DA` 开头，`zlib.decompress` 自带 adler32 校验，能解出来就是真载荷 |
| ZIP 结构 | `50 4B 03 04` 本地头 / `50 4B 01 02` 中央目录 / `50 4B 05 06` EOCD；`flag_bits & 1` 是 ZipCrypto |
| ZipCrypto 尺寸关系 | 密文 = 12（加密头）+ 明文；`method=0` 存储时 `usize` 就是明文长度 |
| 弱提示题 | 提示常给"报错文案 / 版本号 / 文件名"，把**原文**当密码，别把占位符当密码 |
| uuencode | `begin 644 name` … `end`，`(c-32)` 拆 6 bit；与 base64 不同，行首字符标长度 |
| 编码栈 | 这题叠了 zlib→base64→zip→uuencode 四层，建议每层落盘留证，别一路管道到底 |

## 十、一句话总结

**它不是一张"藏着图"的图，而是一个"套了四层壳的信封"：JPEG 尾部塞 zlib，里面是 base64，解开是被人掰歪了头的 ZIP，密码藏在它自己注释里的假报错文案，最后还要过一次 uuencode。**
