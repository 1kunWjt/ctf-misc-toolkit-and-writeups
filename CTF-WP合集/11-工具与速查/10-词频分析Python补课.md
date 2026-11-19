# Python 补课 · 只补这道题用得到的

> 目标：看懂 `逐行详解版.py`，并且能把它压缩成考场版默写出来。
> 下面每一个“结果”都是我实际跑出来的，不是编的。

---

## 0. 五分钟路线

只要依次搞懂这 5 件事，这道题你就通了：

1. `print` 打印 → 看结果
2. `for` 循环 → 把一堆东西一个个处理
3. 认识 4 种数据类型（str / list / dict / tuple）
4. `Counter` → 数数
5. `re.findall` → 按形状抓字符

其余全是语法糖。

---

## 1. 怎么跑、报错怎么看

```bat
python 逐行详解版.py 示例样本.txt
```

报错信息**先看最后一行**，那里写着错误类型；倒数第 2~5 行写着出错的行号。
例如：

```
  File "a.py", line 22, in <module>
    s = s + 1
TypeError: can only concatenate str (not "int") to str
```

意思就是：第 22 行，字符串不能直接加数字。

---

## 2. 变量：就是给数据贴个标签

```python
a = "hello"     # 把字符串 hello 贴上标签 a
b = 123         # 把数字 123 贴上标签 b
print(a)        # 结果: hello
```

改名不影响任何东西，`s`、`text` 这些名字只是方便你读懂。

---

## 3. 四大数据类型（本脚本只用到这 4 个）

| 类型 | 长什么样 | 装什么 | 本脚本里叫 |
|---|---|---|---|
| **str** 字符串 | `'abc'` | 一串字符 | `text`、`s`、`answer` |
| **list** 列表 | `['a', 'b']` | 一堆东西，有顺序 | `items`、`rank` |
| **dict** 字典 | `{'a': 2}` | 键 → 值 | `counter` |
| **tuple** 元组 | `('a', 2)` | 几个值打包在一起 | `rank` 里的每个元素 |

---

## 4. 字符串 str：最常用的 12 个方法

（左列代码 → 右列是实际跑出来的结果）

| 写法 | 结果 | 说明 |
|---|---|---|
| `'Hello'.lower()` | `'hello'` | 全变小写 |
| `'Hello'.upper()` | `'HELLO'` | 全变大写 |
| `'a b\nc'.split()` | `['a', 'b', 'c']` | 按空白切开，**顺便把空白删掉** |
| `','.join(['a','b'])` | `'a,b'` | 用逗号把列表拼成字符串 |
| `''.join(['a','b'])` | `'ab'` | 什么分隔符都不要，直接拼 |
| `'  abc  '.strip()` | `'abc'` | 去掉两端空白 |
| `'abc'.replace('b','X')` | `'aXc'` | 替换 |
| `len('abc')` | `3` | 长度 |
| `'a' in 'abc'` | `True` | 是否包含 |
| `' '.isspace()` | `True` | 是不是空白字符 |
| `'7'.isdigit()` | `True` | 是不是数字 |
| `str(5) + 'x'` | `'5x'` | **数字要先 str() 变成字符串才能加** |

### 索引和切片（从 0 开始数！）

| 写法 | 结果 |
|---|---|
| `'abc'[0]` | `'a'` ← 第 1 个是 0 |
| `'abc'[-1]` | `'c'` ← 负数表示倒数 |
| `'abcdef'[0:2]` | `'ab'` ← 左闭右开 |
| `'abcdef'[::-1]` | `'fedcba'` ← **倒序，非常好用** |

> `[::-1]` 的记法：`[开始:结束:步长]`，步长 -1 就是倒着走。题目要“从少到多”时直接用它。

---

## 5. 列表 list

```python
items = ['ab', 'ca']     # 建一个列表
items.append('bb')       # 尾部追加 → ['ab','ca','bb']
print(len(items))        # 3
print(items[0])          # 'ab'
```

遍历（把每个元素取出来）：

```python
for one in items:
    print(one)           # 依次打印 ab / ca / bb
```

---

## 6. 字典 dict 和计数器 Counter

字典就是“查表”：给一个键，拿到一个值。

```python
d = {'x': 1, 'y': 2}
print(d['x'])            # 1        （键不存在会报 KeyError）
print(d.get('z', 0))     # 0        （键不存在返回默认值，安全写法）
```

`Counter` 是专门数数的字典，**把字符串丢进去，自动数每个字符**：

```python
from collections import Counter
c = Counter('aab')
print(c)                 # Counter({'a': 2, 'b': 1})
print(c['a'])            # 2
print(c['z'])            # 0        （不存在的字符返回 0，不会报错）
print(c.most_common())   # [('a', 2), ('b', 1)]   ← 已按次数从大到小排好
print(c.most_common(1))  # [('a', 2)]             ← 只要第一名
print(c.most_common()[::-1])  # [('b', 1), ('a', 2)]  ← 反过来（从少到多）
```

**这是整道题的核心。** `most_common()` 返回的是列表，里面每个元素是元组 `(字符, 次数)`。

---

## 7. for 循环的四种写法

```python
# ① 遍历列表
for one in ['a', 'b']:
    print(one)

# ② 数次数（range）
for i in range(3):        # i = 0,1,2
    print(i)

# ③ 既要下标又要元素
for i, ch in enumerate(['a','b']):
    print(i, ch)          # 0 a / 1 b

# ④ 元组解包（本脚本用这种）
for ch, n in [('a', 5), ('b', 3)]:
    print(ch, n)          # 一次取出两个值
```

> `for ch, n in rank` 能同时拿到“字符”和“次数”，就是因为 `rank` 里每个元素是 `(字符, 次数)` 这种两件套。

---

## 8. if 和缩进（Python 最容易错的地方）

```python
if ch.isspace() == False:     # 条件成立才执行下面
    clean = clean + ch        # ← 这行必须比 if 多缩进 4 个空格
```

**Python 靠缩进判断“哪些行属于这个 if/for”，不靠大括号。**
缩进错了就报 `IndentationError: expected an indented block`。

常见写法对照：

| 写法 | 意思 |
|---|---|
| `if x == 0:` | 相等（是 `==` 两个等号，一个等号是赋值） |
| `if x != 0:` | 不相等 |
| `if not x:` | 取反 |
| `if 'a' in s:` | 包含 |

---

## 9. import：用别人写好的工具

```python
import re                                  # 之后写 re.xxx
from collections import Counter            # 之后直接写 Counter
```

区别：`import re` 用的时候要带前缀 `re.findall(...)`；
`from ... import Counter` 可以直接用 `Counter(...)`。

---

## 10. 正则 30 秒版（re）

正则就是“用形状描述字符串”。

| 写法 | 意思 | 实测例子 |
|---|---|---|
| `\{` `\}` | 字面的花括号（元字符要转义） | — |
| `( )` | 捕获组：**只返回括号里的内容** | `re.findall(r'(\d)(\d)', '1234')` → `[('1','2'), ('3','4')]` |
| `.` | 任意一个字符 | — |
| `*` | 前面的东西 0 次或多次 | — |
| `?` | 非贪婪，能少则少 | `{a}{b}` → 得到 `a`、`b` 两段，不会粘成一段 |
| `\d+` | 一串数字 | `re.findall(r'\d+', 'a1b22c333')` → `['1','22','333']` |
| `re.S` | 让 `.` 也能匹配换行 | 见下面 |

### `re.S` 到底有多重要（真实对比）

```python
re.findall(r'\{(.*?)\}', 'x{ab\ncd}y', re.S)   # → ['ab\ncd']   抓到了
re.findall(r'\{(.*?)\}', 'x{ab\ncd}y')         # → []           一行都抓不到！
```

**结论：只要片段可能跨行，第三个参数必须写 `re.S`。**

### 本脚本的正则拆解

```
r"\{(.*?)\}"
 │  │ │    │
 │  │ │    └── 右花括号（转义）
 │  │ └─────── 任意字符，尽量少匹配
 │  └───────── 捕获组：findall 只返回它
 └──────────── 左花括号（转义）
```

---

## 11. 读文件：三种写法，建议背第一种

```python
# ① 最稳：二进制读，再自己解码，编码不对也不会崩（本脚本用的）
text = open(path, "rb").read().decode("utf-8", "ignore")

# ② 明确知道编码时
text = open(path, encoding="gbk").read()

# ③ 题目文件是 UTF-8 且很干净
text = open(path, encoding="utf-8", errors="ignore").read()
```

`"ignore"` 的意思是：遇到解不开的字节就跳过，**绝不抛异常**，代价是可能丢几个字符。
`"utf-8"` 换 `"gbk"`：中文题目文件很多是 GBK 存的，出现乱码就换它。

---

## 12. 报错对照表（照着找原因）

| 报错 | 原因 | 怎么修 |
|---|---|---|
| `IndentationError` | 缩进不对 | 同级的行必须对齐，if/for 下面要缩进 |
| `SyntaxError` | 少括号 / 少引号 / 少冒号 | 检查 `(` `)`、`'`、`:` 配对 |
| `NameError: name 'xx' is not defined` | 变量名打错或没定义 | 检查拼写 |
| `TypeError: can only concatenate str` | 字符串直接加了数字 | 用 `str(数字)` 转一下 |
| `IndexError: list index out of range` | 下标越界 | `items[0]` 时先确认列表不空 |
| `KeyError` | 字典里没有这个键 | 改用 `.get(键, 默认值)` |
| `UnicodeDecodeError` | 编码猜错 | 换 `gbk`，或加 `errors="ignore"` |
| `AttributeError: 'list' object has no attribute 'lower'` | 对列表用了字符串方法 | 先确认变量是 str 还是 list |
| `re.error: nothing to repeat` | 正则里 `*` `+` 没东西可重复 | 检查 `.*?` 前面有没有 `.` |
| 输出是空行 | `findall` 一条都没匹配到 | 打印 `len(items)` 看是不是 0；检查括号是否写错 |

---

## 13. 详细版 ↔ 考场版 逐行对照

考场版之所以短，只是把“循环 + 拼接”换成了 `join`。功能完全一样。

| 详细版（好懂） | 考场版（好写） |
|---|---|
| `s = ""`<br>`for one in items:`<br>`    s = s + one` | `s = "".join(items)` |
| `clean = ""`<br>`for ch in s:`<br>`    if ch.isspace() == False:`<br>`        clean = clean + ch` | `s = "".join(s.split())` |
| `answer = ""`<br>`for ch, n in rank:`<br>`    answer = answer + ch` | `"".join(c for c, _ in rank)` |
| `counter = Counter(s)`<br>`rank = counter.most_common()` | `Counter(s).most_common()` |

**记忆法：** 凡是“空字符串 + for + 拼接”，都能写成 `"".join(...)`。

---

## 14. 手写代码最容易错的 6 个点

1. **中文标点**：`，` `：` `（` 这些中文符号 Python 不认，必须用英文 `,` `:` `(`。
2. **冒号漏了**：`if x:` / `for i in y:` 结尾必须有冒号。
3. **缩进用了 Tab 又用空格**：统一用 4 个空格。
4. **`=` 和 `==`**：赋值一个等号，比较两个等号。
5. **括号配对**：`Counter(s).most_common()` 三个括号，检查是否各有一个闭合。
6. **反斜杠**：`r"\{(.*?)\}"` 前面有 `r` 就不用写双反斜杠；没有 `r` 就要写成 `"\\{(.*?)\\"`。

---

## 15. 考前 10 分钟做什么

1. 默写考场版 15 行一遍，跑通 `示例样本.txt`，看到 `miscfreq`。
2. 把括号换成 `[]` 试一次，确认自己会改正则。
3. 把 `.lower()` 删掉试一次，看懂“区分大小写”是什么效果。
4. 把 `most_common()` 改成 `[::-1]` 试一次。
5. 背下这四个开关的位置，就够应付绝大多数变体了。
