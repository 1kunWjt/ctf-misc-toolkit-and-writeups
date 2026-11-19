# apple — Writeup

> 平台未在附件中标注（题号 19，附件为 `attachment.zip`） · 分类：Pwn（堆 / 格式化字符串 / 有符号越界） · 难度：★★★★☆

| 项目 | 内容 |
|---|---|
| 题目名 | apple |
| 分类 | Pwn / glibc 堆 + 格式化字符串 |
| 附件 | `attachment.zip` → `pwn`（14472 字节）+ `libc.so.6`（2220400 字节，Ubuntu GLIBC 2.35）+ `ld-linux-x86-64.so.2` |
| 一句话 | 数组下标用**有符号** `jg` 做上界检查，于是负数下标把 `ptrs[]`/`sizes[]` 打通，一次 write 就变成任意写 |
| 结果 | 未完成（原语链已静态打通到"任意写"，最后的控制流劫持未构建、未验证，见第六节） |

**最终答案**

```
（未取得 flag；本机无 Linux 运行环境，exploit 未执行验证）
```

## 一、题目长什么样（先建立直觉）

一个典型的 note 题：16 KB 的 ELF64，PIE、Full RELRO（`BIND_NOW`）、NX、Canary，动态链接到题目自带的 `libc.so.6`。菜单只有三项：

```
1. Add Note
2. Delete Note
3. Show Note
```

有意思的是 `main` 的结构——**不是**常见的 `while(1)` 里分发：

```
1209: initenv()        # setbuf(stdin/stdout/stderr, NULL)
1550: loop()           # 菜单循环：1→add  2→del  3→show  其它→跳出
15e7: edit()           # 循环结束后，只给一次写内容的机会
```

也就是说：`add` / `del` / `show` 可以无限次用，但"往 chunk 里写数据"的 `edit` **只执行一次**，写完 `main` 就返回退出。这个设计直接决定了整题的 exploit 形态——所有铺垫都要在循环里做完，最后一发 `edit` 必须是致命一击。

## 二、思路总览

1. 反编译 8 个函数，还原 `.bss` 里的数据结构布局（`ptrs[16]`、`sizes[16]`、全局 `idx`）；
2. 找到三个洞：删完不清指针（UAF / double free）、`printf(chunk)` 格式化字符串、以及**下标检查是有符号比较** `jg 0xf`；
3. 负数下标能让 `sizes[idx] = size` 写到 `ptrs[]` 的**半字**上 → 用两次 `add` 拼出一个完整的 64 位任意指针；
4. `edit` 就是 `read(0, ptrs[idx], sizes[idx])`，于是上面那个任意指针 + 已知长度 = **任意地址写**；
5. 泄漏走"释放一个超过 tcache 范围的 chunk 进 unsorted bin，再用 `show` 把 `fd` 当字符串打出来"；
6. 最后一发写向 `_IO_2_1_stdout_`，做 FSOP。

第 3、4、5 步在原语层面是通的，第 6 步只做了目标选择与偏移核对，未构建字节流。

## 三、逐步复现

### 3.1 第一步：确认保护与 libc 指纹

```
Type: DYN（PIE）              FLAGS: BIND_NOW（Full RELRO）
GNU_STACK: RW                 （NX 开）
导入: free malloc read puts printf setbuf __stack_chk_fail
      + stdout/stdin/stderr 三个 copy relocation（0x4020/0x4030/0x4040）
libc: GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.8)
```

怎么读这个输出：**Full RELRO 意味着 GOT 不可写**，所以"改 GOT"这条最舒服的路从一开始就没戏；`__free_hook` / `__malloc_hook` 虽然在这份 libc 的 `.dynsym` 里还挂着（`0x2214a8` / `0x2214a0`），但 glibc 2.34 起就不再调用了——两个符号在、功能不在，是本题最容易踩的坑（见第五节）。

### 3.2 第二步：还原 `.bss` 布局，这是本题的钥匙

`objdump` 出来的 8 个函数（stripped，按 `main` 的调用关系命名）：

| 地址 | 我给的命名 | 作用 |
|---|---|---|
| `0x1209` | `initenv` | 三次 `setbuf(stream, NULL)` |
| `0x1277` | `menu` | `puts` 三行菜单文字 |
| `0x12d6` | `readin` | `puts(prompt)` → `printf(">>>")` → `read(0, dst, 4)` → `puts("")` |
| `0x1355` | `add` | 读 index、读 size、`malloc(size)`，存进两个数组 |
| `0x1417` | `del` | 读 index，`free(ptrs[idx])` |
| `0x14a1` | `show` | 读 index，`printf(ptrs[idx])` |
| `0x1550` | `loop` | 菜单循环 + 三项分发 |
| `0x15e7` | `edit` | 读 index，`read(0, ptrs[idx], sizes[idx])` |
| `0x16b6` | `main` | `initenv` → `loop` → `edit` |

关键在 `add` 的两条存值指令（`0x13d3` 与 `0x13f2`）：

```
13bd: call malloc
13da: mov [rdx+0x4060], rcx     # ptrs[idx]  = malloc 返回值（qword）
13f9: mov [rcx+0x40e0], eax     # sizes[idx] = size（dword）
```

配合 `.bss` 边界（`0x4020` 起、长 `0x108`）可以推出完整布局：

```
0x4020  stdout      ← copy relocation
0x4030  stdin
0x4040  stderr
0x4060  ptrs[16]    8 字节 × 16 = 0x4060..0x40df
0x40e0  sizes[16]   4 字节 × 16 = 0x40e0..0x40ff
0x4120  idx         （全局 int，add/del/show/edit 共用这一个变量）
```

怎么做这一步：`0x4060 + 16*8 = 0x40e0`、`0x40e0 + 16*4 = 0x4120`，两处紧邻关系完全对得上，说明 `ptrs` 与 `sizes` 是**连续两块数组**，中间没有任何哨兵。

### 3.3 第三步：三个洞，先挑最干净的

**(a) 删完不清指针**（`0x1417`）：只 `free(ptrs[idx])`，既不判空也不置零。于是 double free、UAF 都成立。

**(b) 格式化字符串**（`0x14a1`）：`printf(ptrs[idx])`——缓冲区当格式串。可惜 `add` 不读内容，循环期间没有任何办法往 chunk 里写可控字节，所以它**只能当"原始字节打印机"用**（泄漏），做不了 `%n` 写。

**(c) 有符号上界检查**（`0x13a7`、`0x144b`、`0x14d5`、`0x1635`）：

```
13a7: mov  eax,[0x4120]
13ad: cmp  eax,0xf
13b0: jg   <跳过整个 add>
```

`jg` 是**有符号**比较，只挡 `> 15`，不挡负数。下限完全没人管。

三个洞里，(c) 是最干净的：它不需要堆状态配合，只要连打几次 `add` 就能直接改数组本身。

### 3.4 第四步：负数下标 → 任意指针 → 任意写

把负数下标代进两个写指令的地址公式（`ptrs` 基址 `0x4060`、`sizes` 基址 `0x40e0`、`add` 先写 `ptrs[idx]` 再写 `sizes[idx]`）：

| 下标 | `ptrs[idx]` 落点 | `sizes[idx]` 落点 |
|---|---|---|
| -1 | `0x4058`（填充区） | `0x40dc` = `ptrs[15]` **高 4 字节** |
| -2 | `0x4050`（填充区） | `0x40d8` = `ptrs[15]` **低 4 字节** |
| -3 | `0x4048`（填充区） | `0x40d4` = `ptrs[14]` 高 4 字节 |
| -4 | `0x4040` = **stderr** | `0x40d0` = `ptrs[14]` 低 4 字节 |
| -6 | `0x4030` = **stdin** | `0x40c8` = `ptrs[13]` 低 4 字节 |
| -8 | `0x4020` = **stdout** | `0x40c0` = `ptrs[12]` 低 4 字节 |

于是最干净的一条链是用 **`ptrs[15]`**：下标 `-1` 和 `-2` 的 `ptrs[]` 写落点都在 `.bss` 的填充区（`0x4058` / `0x4050`），完全无害：

```python
add(15, L)        # ptrs[15] = malloc(L)，同时 sizes[15] = L
add(-1, HI)       # ptrs[15] 的高 4 字节 ← HI
add(-2, LO)       # ptrs[15] 的低 4 字节 ← LO
# 此时 ptrs[15] == (HI << 32) | LO，而 sizes[15] 仍是 L
```

然后跳出循环，`edit` 会问你要改哪个 index，答 `15`：

```
15e7 edit: read(0, ptrs[15], sign_extend(sizes[15]))
```

`ptrs[15]` 任意、`sizes[15]` 也任意（`L` 只是 `malloc` 的入参，`malloc` 失败也无所谓，因为紧接着就被覆盖了），**任意地址写任意长度**成立。

注意 `sizes[idx]` 是用 `movsxd` 符号扩展后当 `count` 的，所以 `sizes[15]` 取正数；负数会被解释成天文数字，但那种情况在 `add` 阶段 `malloc` 就先失败了——不影响指针伪造，只是长度不可控。

### 3.5 第五步：拿 libc 泄漏

`show` 是 `printf(chunk)`，会把 chunk 内容当字符串打出来。要打出有用的东西，就让 chunk 里存在"库地址"：

1. `add(0, 0x500)` —— 请求 0x500（> `tcache_max`），chunk 实际大小 0x510；
2. `del(0)` —— 进 unsorted bin，其 `fd` / `bk` 都指向 `main_arena + 96`（libc 地址）；
3. `show(0)` —— `printf` 从这个地址开始按字节打到 `0x00` 为止，libc 指针是 6 字节有效 + 2 字节零，于是**稳定吐出 6 字节 libc 地址**。

拿到这 6 字节后按 `u64(leak.ljust(8, b'\x00'))` 还原，再减去 `main_arena + 96` 相对 `libc_base` 的偏移。

这份 libc 是 stripped（只有 `.dynsym`），但关键符号都导出了，我核对过真实值：

| 符号 | 偏移 | 说明 |
|---|---|---|
| `main_arena` | 不在 `.dynsym` | 需要用 `__libc_start_main` 或 debug 符号定位 |
| `system` | `0x50d70` | 导出 |
| `/bin/sh` 字符串 | `0x1d8678` | `strings -t x` 实测 |
| `_IO_2_1_stdout_` | `0x21b780` | 导出 |
| `_IO_wfile_jumps` | `0x2170c0` | 导出 |
| `setcontext` | `0x539e0` | 导出 |
| `free` / `malloc` / `puts` / `read` | `0xa53e0` / `0xa50a0` / `0x80e50` / `0x1147d0` | 导出 |

### 3.6 第六步：最后一发往哪打

约束：**只有一次连续写**，而且 `edit` 之后 `main` 立刻返回、进程退出，没有任何后续交互。所以这一发必须直接决定控制流。

候选与取舍：

| 目标 | 为什么行 / 不行 |
|---|---|
| GOT | Full RELRO，只读，不行 |
| `__free_hook` | 符号还在（`0x2214a8`），但 2.34 起不再被调用，**改了没反应** |
| 栈上返回地址 | 缺 stack 泄漏，不知道地址 |
| `stdout` copy reloc（PIE+0x4020） | 需要 PIE 基址，本题只有 libc 泄漏 |
| `_IO_2_1_stdout_` + FSOP | libc 可写、地址已知、一次连续写足够铺开 `FILE` + 伪造 `_wide_data` + `_wide_vtable` |

FSOP 的方向很明确：把 `_IO_2_1_stdout_`（`0x21b780`）整个覆盖成伪造的 `FILE`，`vtable` 指向 `_IO_wfile_jumps`（`0x2170c0`），`_wide_data` 指向同一段写入里的伪造区，让 `exit` 时的 `_IO_flush_all` 最终调到 `_wide_vtable->__doallocate`（指向 `system` 或 one_gadget）。同一次写里还能顺手铺一个 `ucontext` 给 `setcontext`（`0x539e0`）做备用。

这一步我只确认了"地址可写、符号存在、一次写够长"，**字节流没有构造也没有验证**，原因见第六节。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| 有符号上界检查 | `cmp eax,0xf` + `jg`，只挡正溢出 | 负数下标直接改数组本身 | 所有"数组 + 用户可控下标"的题，先看 `jg` 还是 `ja` |
| 数组相邻布局 | `ptrs[]` 与 `sizes[]` 连续排布 | 负数下标能写到另一个数组的半字上 | 反编译时永远先画 `.bss` 图 |
| 半字（dword）写 | `mov [mem], eax` 只写 32 位 | 两次 `add` 拼出一个完整 64 位指针 | 无 8 字节写原语时拼指针的标准手法 |
| unsorted bin 泄漏 | 大于 tcache 上限的 chunk 释放后 `fd`/`bk` 指向 `main_arena` | 换一个 libc 基址 | 所有 glibc 堆题的第一发泄漏 |
| `printf(chunk)` 当泄器 | 缓冲区当格式串，可泄漏到 `0x00` 为止 | 循环里拿不到可控内容，只能这么用 | 格式化字符串题的"只读"分支 |
| Full RELRO | GOT 只读 | 排除最省事的目标 | 决定了堆题必须打 `_IO` / 栈 / hook |
| `.dynsym` 冻结 | 2.35 的 libc 里 `__free_hook` 只剩符号 | 别把时间浪费在它身上 | 2.34+ 的 glibc 一律先确认 hook 是否还在调用路径上 |

## 五、踩坑与陷阱

1. **`__free_hook` 是陷阱**。`readelf -s libc.so.6` 能查到 `__free_hook` 与 `__malloc_hook`，很诱人；但 glibc 2.34 起 `free()` 不再走 hook，改完等于没改。判断依据是版本号（这里有 `Ubuntu GLIBC 2.35-0ubuntu3.8` 的字符串），不是符号存不存在。
2. **`edit` 只有一次**。第一反应容易把它当成"常规 edit 函数"，写脚本时反复调用会发现第二次就直接退进程了。菜单里退出方式是"输入 1/2/3 以外的数字"。
3. **`printf(ptrs[idx])` 不是"能写"的格式化字符串**。循环期间没有写 chunk 的途径，`%n` 需要的格式串放不进去；别在这上面耗时间。
4. **负下标会顺手改 `stdin`/`stdout`/`stderr`**。下标 `-4`/`-6`/`-8` 的 `ptrs[]` 写会覆盖这三个 copy relocation，一旦覆盖 `stdout`，之后所有 `puts`/`printf` 都会踩到假 `FILE`。所以拼指针**优先用 `ptrs[15]`（下标 `-1`/`-2`）**，落点全在填充区。
5. **`sizes[]` 的符号扩展**。`read(0, ptr, movsxd(sizes[idx]))`——`sizes[idx]` 一旦是负数，长度就是天文数字，行为取决于内核 `MAX_RW_COUNT` 夹取，别指望可控。

## 六、卡点与正解方向

**已确认（有字节码与符号表支撑）**

- 程序骨架：`initenv → loop(add/del/show) → edit`，`edit` 只执行一次；
- `.bss` 布局：`ptrs[16]@0x4060`、`sizes[16]@0x40e0`、`idx@0x4120`；
- 下标检查是 `jg 0xf`（有符号），负下标畅通；
- **任意指针**：`add(-1,HI)` + `add(-2,LO)` 精确覆盖 `ptrs[15]`，落点无害；
- **任意写**：`edit` 的 `read(0, ptrs[15], sizes[15])`；
- **libc 泄漏**：`add(0,0x500)` → `del(0)` → `show(0)` 打 unsorted bin 的 `fd`；
- 这份 libc 的真实偏移：`system=0x50d70`、`_IO_2_1_stdout_=0x21b780`、`_IO_wfile_jumps=0x2170c0`、`setcontext=0x539e0`、`/bin/sh=0x1d8678`。

**卡在哪**

1. `main_arena` 不在 `.dynsym` 里，`libc_base` 的换算偏移没定下来（需要在 Linux 上用 debug 符号或 gdb `p &main_arena` 取，本机无 Linux）；
2. 本机没有 `one_gadget`（也没装 ruby），`__doallocate` 的目标只能先写 `system`，而 `system` 需要一个 `rdi` 指向 `/bin/sh` 的时机，FSOP 那条路的寄存器现场没验证；
3. FSOP 的字节流（`_flags`、`_mode`、`_wide_data` 指向哪、`_wide_vtable` 的偏移）一个字节都没跑过，不敢往 WP 里写具体字节。

**正解方向**

1. **先补 `main_arena` 偏移**。在 Linux 上 `patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath .` 挂上题目自带 libc，`gdb` 里 `p &main_arena`，一次就定死。这一步不做，后面全是空中楼阁。
2. **FSOP 走 "house of apple 2" 的标准形态**：`_IO_2_1_stdout_` 铺假 `FILE`，`vtable = _IO_wfile_jumps`，`_wide_data` 指向同一段写入内的伪造区，`_wide_vtable->__doallocate` 指向目标。这条路的好处是**只吃一次连续写**，正好匹配本题"`edit` 只有一次"的设计。
3. **备选：改 `setcontext`**。`setcontext` 是导出的（`0x539e0`），如果能顺手让 `exit` 路径上的某个函数指针指过去，`rdi` 指向我们同一次写里铺好的 `ucontext`，就能做栈迁移 + ROP。缺点是同样需要一个"可写函数指针"的落点，比 FSOP 多一次猜想。
4. **别忽略 `ptrs[14]`**。用下标 `-3`/`-4` 也能拼 `ptrs[14]`，代价是顺手覆盖 `stderr`（本程序不用 `stderr`，其实是安全的）。如果 `ptrs[15]` 那条路被"最后一次 edit 前的 `puts`"卡住，可以换这个槽位做第二次落点铺垫。

## 七、赛场 20 分钟行动清单

1. `readelf -h -l -d -s` + `strings libc.so.6 | grep "GNU C Library"`，把版本与保护钉死（3 分钟）。
2. `objdump -d` 全量，给 8 个函数命名，画出 `.bss` 三块数组的边界（6 分钟）。
3. 专门找 `cmp ...; jg` 这类有符号上界，确认负下标可用（2 分钟）。
4. 写"任意指针 + 任意写"的三行 `add`，本地用 `gdb` 断在 `edit` 的 `read` 上核对 `rsi`/`rdx`（5 分钟）。
5. 泄漏：`add(0,0x500)` → `del(0)` → `show(0)`，看回包有没有 6 字节非 ASCII（2 分钟）。
6. 定 `main_arena` 偏移 → 选 FSOP 目标（2 分钟）。

> 超过 45 分钟还在"最后一发往哪打"，先跳题：这类题的原语链能建起来就已经拿到大半分数，别在 FSOP 字节流上死磕。

## 八、附件与脚本

- `files/tempdir/PWN附件/attachment.zip` → `attachment/pwn`、`attachment/libc.so.6`、`attachment/ld-linux-x86-64.so.2`：题目原始附件，只读，未改动；
- 本文所有地址、指令、`.rodata` 字符串、libc 偏移均来自对这些文件执行 `readelf -W -s` / `readelf -W -l` / `objdump -d -M intel` / `strings -a -t x` 的真实输出；
- exploit 未落盘（本机无法运行 ELF）。在 Linux 上建议按 `src/` 习惯新建 `exp_apple.py`，把 3.4 的三行 `add` 与 3.5 的三步泄漏先跑通，再补 FSOP。

> 说明：本题 flag 未取得，正文不含任何虚构回显。附件里 `libc.so.6` 的 `system` 偏移为 `0x50d70`，与公开的 Ubuntu GLIBC 2.35-0ubuntu3.8 一致，但 `main_arena` 仍需现场取。
