# muslexam — Writeup

> 平台未在附件中标注（题号 20，附件为 `attachments.zip`） · 分类：Pwn（musl + 堆） · 难度：★★★★★

| 项目 | 内容 |
|---|---|
| 题目名 | muslexam |
| 分类 | Pwn / musl libc 堆 |
| 附件 | `attachments.zip` → `musl-exam`（18584 字节）+ `libc.so`（707056 字节，musl libc 1.2.2） |
| 一句话 | 菜单题故意送一个 puts 泄漏，真正的坑是 `edit` 从 `ptr-0x10` 开始写——在 musl 里这正好盖住 in-band slot 元数据 |
| 结果 | 未完成（程序与 libc 静态分析完成，原语定位到 in-band 元数据，exploit 未构建、未验证，见第六节） |

**最终答案**

```
（未取得 flag；本机无 Linux 运行环境，exploit 未执行验证）
```

## 一、题目长什么样（先建立直觉）

一个**没有 strip** 的 ELF64 菜单题，符号表直接把函数名端出来了：

```
0x11c9 initenv   0x122e menu     0x1298 add      0x140e show
0x14ae edit      0x1595 delete   0x167a gift     0x16a3 main
```

`main` 是个 `while` 循环：`menu()` → `scanf("%d", &choice)` → `switch`（跳表在 `.rodata:0x2084`）→ 1 add / 2 show / 3 edit / 4 delete / 5 exit。另外 `main` 里有一句非常刺眼的比较：

```
16f0: cmp eax,0x5
16f3: jg  1721
...
1721: cmp eax,0xda5c7f     # 14328703
1726: je   1764            # → call gift
```

也就是说输入 `14328703` 会走进 `gift`，而 `gift` 干的事是：

```
167a gift:
1682: mov rax,[rip+0x293f]     # 3fc8 → puts@GOT
168c: lea rax,[rip+0x9cd]      # 2060 → "gift for you: %p\n"
169b: call printf
```

**这就是白送的 libc 泄漏**。作者把"最难的第一步"直接给了你，说明后面很难。

## 二、思路总览

1. 读 `add` / `show` / `edit` / `delete`，把 `.bss` 里的 notes 表结构还原出来；
2. 确认 `delete` 是干净的（既置空 size 又置空 ptr），`show` 只有一次且是**任意地址读 8 字节**；
3. 确认唯一的 bug 是 `edit` 的 `read(0, ptr-0x10, size)`——少了 0x10 的偏移；
4. 用 `gift` 泄 `puts` → 在题给 `libc.so` 上算出 musl 基址；
5. 用 `show`（只有一次）读 `environ`，换一个栈地址；
6. 关键：这题的 `libc.so` 是 **mallocng** 时代的 musl 1.2.2，`ptr-0x10` **不是** glibc/musl-old 那种 `psize/csize` chunk 头，而是 in-band slot 元数据——不改思路就会在第一节就写错。

第 1~5 步有字节码/符号表支撑，第 6 步只做到"确认它不是老式 chunk 头"，没做到"用 mallocng 语义造出任意写"。

## 三、逐步复现

### 3.1 第一步：确认保护、libc 版本、notes 表布局

```
Type: DYN（PIE）          INTERP: /lib/ld-musl-x86_64.so.1
FLAGS: BIND_NOW（Full RELRO）   GNU_STACK: RW（NX 开）   Canary 在
字符串: musl libc (x86_64) / Version 1.2.2
```

`.data` / `.bss` 里的布局（`objdump -s -j .data` + 反编译交叉验证）：

```
0x4008  show_count   （.data 里是 01 00 00 00 → 初值 1，show 只能用一次）
0x4040  notes[16]    每项 16 字节：{ size (qword) @+0x0, ptr (qword) @+0x8 }
        第 i 项 size 在 0x4040+16*i，ptr 在 0x4048+16*i
```

`add` 的存值指令（`0x1356` 与 `0x137b`）正好对上：

```
1348: mov rcx,rdx
134b: shl rcx,0x4                 # rcx = idx * 16
1356: mov [rcx+0x4040], rax       # notes[idx].size = size
1365: call malloc
137b: mov [rdx+0x4048], rcx       # notes[idx].ptr  = malloc 返回值
```

**注意 `add` 是"分配 + 立刻写入内容"**：`0x13e6 call read` 的参数是 `rsi = notes[idx].ptr`、`edx = notes[idx].size`。所以 chunk 内容完全可控，这点比很多同类题友好。

### 3.2 第二步：四个功能逐个核对，找出唯一真 bug

**add（0x1298）**：`scanf("%u", &idx)` → `cmp rax,0xf; ja`（**无符号**比较，负数被挡）→ `scanf("%u", &size)` → `cmp rax,0x2000; ja`（size 上限 0x2000）→ 存 size、`malloc(size)`、存 ptr、`read(0, ptr, size)`。注意：**不检查该下标是否已分配**，重复 `add` 同一个下标只会覆盖指针（旧 chunk 泄漏，但没释放）。

**show（0x140e）**：仅当 `show_count != 0` 时可用；`scanf("%llu", &addr)` 之后：

```
1462: mov rax,[rbp-0x18]     # addr
1466: mov rax,[rax]          # 解引用
1483: call printf            # "val: %#llx"
1488: sub show_count, 1
```

**任意地址读 8 字节，全局只有一次**（初值 1）。

**delete（0x1595）**：`free(ptr)` 之后**同时**把 `notes[idx].size` 与 `notes[idx].ptr` 置 0（`0x1635` 和 `0x164f`）。干净，没有 UAF、没有 double free。

**edit（0x14ae）**：读 idx、判 `idx ≤ 15` 且 `ptr != 0`，然后：

```
1544: lea rax,[rip+0x2af5]   # 4048 → notes[idx].ptr
154b: mov rax,[rdx+rax]      # rax = notes[idx].size
1561: mov rdx,[rcx+rdx]      # rdx = notes[idx].ptr
1565: lea rcx,[rdx-0x10]     # ← 缓冲区 = ptr - 0x10
1574: call read              # read(0, ptr-0x10, size)
```

`lea rcx,[rdx-0x10]` 就是全题唯一的漏洞：写入起点比用户缓冲区**早 16 字节**，长度仍是 `size`。

### 3.3 第三步：`ptr-0x10` 到底盖住了什么

这是本题最容易写错的地方。先看 `malloc` / `free` 的真实落点（musl 的导出符号是 `endbr64; jmp` 桩）：

```
0x27d30 free:    endbr64; jmp 0x287f0
0x27e40 malloc:  endbr64; jmp 0x29780
```

把 `0x287f0` 那段（真正的 `free`）读出来，关键指令是：

```
2880a: call 0x282f0                    # 由用户指针反查它所属的 group/meta，返回 meta
2880f: movzx edx,BYTE PTR [r9-0x3]     # 读 p-3
2881c: and  ecx,0x1f                   # 低 5 位 = slot 索引
2884e: shr  dl,0x5                     # 高 3 位 = offset 类别
28866: cmp  dl,0x4 / jbe ...           # 类别要查表，越界就 hlt
288b7: mov  WORD PTR [r9-0x2],dx       # 写 p-2 的 2 字节
288c3: mov  BYTE PTR [r9-0x3],0xff     # 写 p-3 = 0xff（标记释放）
```

也就是说：**用户指针前面那 16 个字节里，`p-3` / `p-2` 是 in-band 的 slot 元数据（索引 + offset 类别 + 释放标记），`free` 靠它们定位 slot**。而 `meta` 结构里 `+0x20` 是页对齐的 group 指针、`+0x10` 是一个偏移量（`28823` / `2882d` / `2884a` 三处访问）。

结论：`edit` 的 `ptr-0x10` 覆盖区**正好包含 `p-3` 与 `p-2`**。这不是"改 chunk size"，是"改 slot 索引与类别"。

为什么必须说清楚：如果你按 glibc/老 musl 的思路去找 `p-8` 的 `size` 字段，会发现那里既不是 size 也不是可用的长度（老 musl 简单分配器才是 `psize/csize` 在 `p-16/p-8`）。这份 `libc.so` 是 **musl 1.2.2**，从 1.2.0 起换成了 mallocng，`free` 里那一堆 `hlt` 就是 mallocng 的完整性检查。搞错这一点，后面所有推导都是错的。

### 3.4 第四步：泄漏链

```
gift:  puts@GOT（ELF 内 0x3fc8）→ printf("gift for you: %p\n")   → musl 基址
show:  一次任意地址读 → 读什么？
```

题给 `libc.so` 是**带完整 `.dynsym`（1704 条）**的，符号直接可用（全部为我用 `readelf -W -s` 实测）：

| 符号 | 偏移 |
|---|---|
| `puts` | `0x5e2f0` |
| `system` | `0x4e0c0` |
| `read` | `0x72740` |
| `mprotect` | `0x40de0` |
| `__libc_start_main` | `0x1aff0` |
| `environ` | `0xafc20` |
| `exit` / `_Exit` | `0x15090` / `0x1b6b0` |
| `atexit` / `__cxa_atexit` | `0x1ba00` / `0x1b950` |

`show` 唯一的那一次，最值钱的读法是 `environ`（`libc_base + 0xafc20`）——拿到栈地址，才有机会谈"覆盖返回地址"。所以顺序是：先 `14328703` 拿 libc 基址，再用 `show` 读 `environ`。

### 3.5 第五步：musl 的 exit 路径（为什么它比 glibc 好打）

`exit`（`0x15090`，31 字节）三连调用，符号表里给了前两个的名字，第三个是内部函数：

```
15097: call 0x1b880    # __funcs_on_exit
1509c: call 0x75e10    # __stdio_exit
150a3: call 0x5a100    # 另一处清理
150aa: call 0x1b6b0    # _Exit
```

再读 `__cxa_atexit`（`0x1b950`）就能把 atexit 表的三个全局变量定位出来：

```
1b96d: cmp QWORD PTR [0xafc48],0x0      # funcs 指针（初值 0xad560，内置数组）
1b977: movsxd rdx,DWORD PTR [0xafe64]   # count（当前条数）
1b98d: mov [rax+rdx*8+0x8],rbp          # funcs[count].func
1b995: mov [rax+rdx*8+0x108],rbx        # funcs[count].arg
1b9a3: mov DWORD PTR [0xafe64],ecx      # count++
```

于是得到三个真实常量：`funcs` 指针在 `0xafc48`、`count` 在 `0xafe64`、内置数组在 `0xad560`（满 32 条后 `malloc(0x208)` 换新数组）。**这是一条比 glibc `__exit_funcs` 干净得多的链**——musl 的 atexit 项不做指针 mangling，`func` 是裸函数指针，`arg` 直接进 `rdi`。

### 3.6 第六步：还差的最后一步

`edit` 给我的写能力是"从 `p-0x10` 起写 `size` 字节"，`p` 是堆指针。要把它变成"写到 `0xafc48` / 栈上"，中间必须多一跳。可选的 musl 常见跳板：

1. **骗 slot 索引**：`edit` 覆盖 `p-3` 的低 5 位，`free` 就会去操作同一个 group 里**另一个 slot** 的账。若那个 slot 正好是另一个仍在使用的 note，就得到两个指向重叠区的 note → 之后 `edit` 一个就能改另一个的"内容"；
2. **骗 offset 类别**：`p-3` 的高 3 位决定 offset 类别（`cmp dl,0x4` / `cmp dl,0x5` 分支），改错会让 `free` 用错误的偏移算 slot 基址；
3. **拿下 group 的 meta**：mallocng 的 `meta` 与 slot 同在一个 group 内，理论上可以用相邻 slot 的越界写碰到 meta 里的页指针（`meta+0x20`），一旦伪造成功，下一个 `malloc` 就会返回我们指定的地址。

这三条都属于"知道往哪打、但没验证"，所以本文不写具体字节。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| in-band 元数据 | mallocng 把 slot 索引/释放标记存在 `p-3`、`p-2` | `edit` 的 `-0x10` 偏移正好覆盖它们 | 所有 musl 1.2+ 堆题 |
| mallocng | musl 1.2.0 起的分配器，用 `meta` 描述 group | 老式 `psize/csize` 那套完全不适用 | 判断 musl 题难度先看版本号 |
| `hlt` 完整性检查 | mallocng 校验失败直接 `hlt` 崩溃 | 解释"为什么改错一个字节就死" | musl 堆题的调试关键 |
| 白送泄漏（gift） | 硬编码 magic `0xda5c7f` 走 `gift`，打 `puts@GOT` | 省掉最难的第一步 | 见到"莫名大常量"先试跳表/比较 |
| 任意读（一次性） | `show` 读 `*(u64)addr`，全局一次 | 唯一的信息出口，必须一次用对 | 决定"先泄 libc 还是先泄栈" |
| musl atexit 表 | `funcs` 指针 `0xafc48`、`count` `0xafe64` | 无 mangling，是理想的控制流目标 | musl 题替代 `__free_hook` 的首选 |

## 五、踩坑与陷阱

1. **别把 `ptr-0x10` 当成 chunk 头**。在 glibc 里 `p-0x8` 是 size、老 musl 简单分配器里 `p-0x10/p-0x8` 是 `psize/csize`；但这份 libc 是 musl 1.2.2（mallocng），我实测 `free` 的真实代码里根本没有这两个字段，它读的是 `p-3` 和 `p-2`。按错模型推导，第一步就会 `hlt`。
2. **`show` 只有一次**。`show_count` 初值 1，用完就永久失效；`add`/`delete` 不会重置它。把唯一一次浪费在已知的东西上（比如再泄一次 `puts`）是不可逆的。
3. **`delete` 是干净的**。两个字段都清 0，别指望 UAF 或 double free；重复 `add` 同一个下标只会泄漏旧 chunk，不是"double alloc 重叠"。
4. **下标检查是无符号的**（`ja`），和 apple 那题的 `jg` 相反，负数下标被挡住；`size` 上限 0x2000，且 `add` 里 `read` 的长度等于分配长度——所以 `add` 本身没有溢出，溢出只可能来自 `edit` 那 16 字节的偏移。

## 六、卡点与正解方向

**已确认（字节码 + 符号表 + libc 反汇编支撑）**

- 程序结构：`initenv → menu 循环 → 5 个功能`，跳表在 `.rodata:0x2084`；
- notes 表：`0x4040` 起 16 项，每项 `{size, ptr}`；`show_count` 在 `0x4008`，初值 1；
- `add` = 分配 + 写入内容（内容可控），size ≤ 0x2000，下标无符号检查；
- `delete` = `free` + 双字段清零，无 UAF；
- `show` = 一次性任意 8 字节读；
- **唯一漏洞**：`edit` 从 `ptr-0x10` 起写 `size` 字节；
- `free` 的真实代码用的是 `p-3`（slot 索引 / offset 类别）与 `p-2`（2 字节标记），`meta+0x10` 是偏移、`meta+0x20` 是页指针；校验失败 `hlt`；
- musl 1.2.2 的真实偏移：`puts=0x5e2f0`、`system=0x4e0c0`、`environ=0xafc20`、`funcs=0xafc48`、`count=0xafe64`、内置 atexit 数组 `0xad560`、`__funcs_on_exit=0x1b880`。

**卡在哪**

1. 缺一个"从重叠 slot 到任意地址写"的跳板。`edit` 能改 in-band 元数据，但把"改索引"转成"可控指针"需要精确复现 mallocng 的 group 布局（group 内 slot 的 stride、meta 的位置），这一步没有 Linux 环境就只能在纸上推，风险太高；
2. 本机无 `one_gadget`（无 ruby），`system` 需要 `rdi` 指向 `"/bin/sh"`；如果走 atexit 表，`arg` 是能直接落到 `rdi` 的，这条反而更省事，但前提是能写到 `0xafe64` / `0xafc48`；
3. 栈地址到手后怎么用也没定：`edit` 的写目标始终是堆指针，要改栈必须先有一次任意写。

**正解方向**

1. **先在 Linux 上把 mallocng 的 group 布局打出来**。`patchelf` 挂上题目自带的 `libc.so` 与 musl 的 `ld`，`gdb` 里 `p *get_meta(p)`（或直接看 `p-0x10` 附近的内存），把 stride、meta 偏移量测准。这是唯一能把"纸上推"变成"能跑"的办法。
2. **优先做"重叠 slot"而不是"伪造 meta"**。改 `p-3` 低 5 位让 `free` 记错 slot，代价最小、可控性最高；拿到两个重叠 note 之后，再用一次 `edit` 去覆盖 `funcs` / `count`（`0xafc48` / `0xafe64`），把 `funcs[0].func` 写成 `system`、`funcs[0].arg` 写成一个 `"/bin/sh"` 字符串的地址（musl 里没有现成的可写副本，这个字符串得自己用 `strings -t x libc.so` 找或者塞进堆里），然后 `exit()` 触发。
3. **`environ` 与 flag 路径**。栈地址只有在"能任意写"之后才有用；如果重叠 slot 走得通但写不到 libc，就用栈上的 `__libc_start_main` 返回地址做 ROP（musl 的 gadget 生态与 glibc 不同，`ROPgadget` 要针对这份 `libc.so` 重新跑）。flag 按容器常规在 `/flag` 或 `./flag`，拿到 shell 后先 `ls /`。

## 七、赛场 20 分钟行动清单

1. `readelf -h -l -d` + `strings libc.so | grep -i musl`，先确认是不是 mallocng（版本 ≥ 1.2 就是）；有符号表就别硬啃，直接列出 8 个函数名，`objdump -d` 只读 `add/show/edit/delete`（7 分钟）。
2. 扫 magic 常量：`cmp eax,0xda5c7f` 一眼就是后门，试一下拿到 `puts` 泄漏（2 分钟）。
3. 定位 `edit` 的 `lea ...,[rdx-0x10]`，确认偏移；**同时**在 libc 里确认 `p-16` 是元数据还是 chunk 头（5 分钟）。
4. 规划唯一那次 `show`：先 `environ`，不要浪费（2 分钟）。
5. 剩下的时间全给"把 `p-3` 变成重叠 slot"（剩下的时间）。

> 超过 50 分钟还没把"改 `p-3`"变成"重叠 slot"，先跳题。musl 堆题的性价比极低，除非你已经很熟 mallocng。

## 八、附件与脚本

- `files/tempdir/PWN附件/attachments.zip` → `attachments_unzip/musl-exam`、`attachments_unzip/libc.so`：题目原始附件，只读，未改动；
- 本文所有地址、指令、符号偏移均来自对这两个文件执行 `readelf -W -s` / `readelf -W -l` / `objdump -d -M intel` / `objdump -s` / `strings -a` 的真实输出；
- 关键取证点：`musl-exam` 的 `0x1565: lea rcx,[rdx-0x10]`（漏洞）、`0x1682: mov rax,[rip+0x293f]`（gift 读 `puts@GOT`）、`libc.so` 的 `0x27d30 → 0x287f0`（真正的 `free`）、`0x2880f/0x288b7/0x288c3`（`p-3` / `p-2` 元数据）；exploit 未落盘（本机无法运行 ELF），建议在 Linux 上新建 `exp_muslexam.py`，按 3.4 的两步先拿 libc 基址与栈地址，再按第六节做重叠 slot。

> 说明：本题 flag 未取得，正文不含任何虚构回显。
