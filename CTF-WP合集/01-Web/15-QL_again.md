# QL_again — Writeup

> 平台未在附件中标注（题号 15，附件即整个 fat jar 解包） · 分类：Web（Java 表达式注入） · 难度：★★★★★

| 项目 | 内容 |
|---|---|
| 题目名 | QL_again |
| 分类 | Web / Java 表达式注入（Spring Boot + QLExpress） |
| 附件 | `QL_again.jar`（Spring Boot fat jar，解包后 39 个依赖 jar + 4 个业务类） |
| 一句话 | 用 QLExpress 白名单沙箱挡住所有方法调用，逼你从"构造器 / 字段 / 属性 / 内置函数"四条侧路绕出去 |
| 结果 | 未完全拿下（RCE 未打通，见第六节） |

**最终答案**

```
（未取得 flag；本文只记录已复现的沙箱行为与已验证的原语）
```

## 一、题目长什么样（先建立直觉）

拿到的是一个 Spring Boot fat jar 的解包目录：`BOOT-INF/classes/` 下只有四个类——`org.example.Main`、`org.example.qluntil`、`org.example.NoNetworkSecurityManager`、`org.example.controller.qlcontroller`；`BOOT-INF/lib/` 下是 39 个依赖 jar，其中最关键的是 `QLExpress-3.3.3.jar`。

QLExpress 是阿里的动态表达式引擎，语法接近 Java 子集，能 `new` 对象、调静态方法、读写字段。它的定位是"让业务同学在配置里写表达式"，所以一旦把用户输入直接丢给 `ExpressRunner.execute()`，等价于把 Java 反射面整个交出去。题目名里的 `_again` 说明这是同类题的第二次出现，作者显然知道经典 bypass，于是加了沙箱。

另外两个类暗示了作者的防守思路：`NoNetworkSecurityManager` 是自定义 `SecurityManager`（想掐掉出网），`qluntil` 是"落盘 + 执行"的胶水层。读懂这三个类，题目就透明了。

## 二、思路总览

1. `javap -p -c -constants` 把四个业务类反编译，还原完整调用链与参数名；
2. 认出沙箱配置是 `setForbidInvokeSecurityRiskMethods(true)` + `setSecureMethods({null})`——一个**只含 null 的白名单**；
3. 因为 HTTP 响应只有 `success` / `error`，表达式结果被丢弃，所以必须拿到"有副作用的执行"才算赢；
4. 写一个 `Harness.java` 原样复刻 `qluntil.executeql` 的配置，把候选 payload 批量喂进去，逐条记录 QLExpress 的反应（这是本题唯一可靠的判据）；
5. 在基线之上追加探针，摸清"哪些语法点不走安全检查"。

本题最终没有打通到 RCE，但第 4、5 步产出的沙箱行为表是硬证据，见 3.4 / 3.5，卡点写在第六节。

## 三、逐步复现

### 3.1 第一步：确认 jar 的构成与启动方式

做什么：先看清 `MANIFEST.MF`、`pom.xml`、`application.properties`，确认框架版本与端口。

```
Spring-Boot-Version: 2.6.11
Start-Class: org.example.Main
Build-Jdk-Spec: 1.8
```

`application.properties` 只有一行 `port=8089`。`pom.xml` 里显式声明的只有 `spring-boot-starter-web` / `spring-boot-starter-thymeleaf`（2.7.5）、`QLExpress`（3.3.3）、`javassist`（3.22.0-GA）。

怎么读这个输出：`commons-beanutils-1.9.4`、`commons-lang-2.4`、`commons-collections-3.2.2`、`jackson-databind-2.13.4.2`、`snakeyaml-1.30` 这些"看起来像 gadget"的库**不是作者故意加的**——解开 `QLExpress-3.3.3.jar` 里的 `META-INF/maven/com.alibaba/QLExpress/pom.xml` 可以看到它自己就依赖 `commons-beanutils 1.9.4` 与 `commons-lang 2.4`（`commons-collections` 是 beanutils 的传递依赖），jackson/snakeyaml 是 `spring-boot-starter-web` 带进来的。这一点很重要：别把传递依赖误读成"作者留的链"。

### 3.2 第二步：反编译四个类，还原整条链路

`javap -p -c -constants` 的结果可以压成下面这条链：

- `Main.main`：**先** `System.setSecurityManager(new NoNetworkSecurityManager())`，**再** `SpringApplication.run(Main.class)`。即安全管理器在 Spring 起来之前就装好了。
- `qlcontroller`（`@RestController`）：
  - `test()` 挂 `@GetMapping("/")`，`return "h3ll0"`；
  - `execute(@RequestParam String payload)` 挂 `@RequestMapping("/execute")`（**不限 method**，GET/POST 都行）：先 `qluntil.getql(payload)`，结果等于字面量 `"error"` 就返回 `"error"`，否则 `qluntil.executeql(路径)` 并把它返回的字符串直接吐给 HTTP。
- `qluntil.getql(String payload)`：
  1. 路径 = `"/tmp/" + payload.substring(0, 3) + ".txt"`；
  2. 内容 = `new String(Base64.getDecoder().decode(payload))`；
  3. `System.out.println(内容)`（顺手把解码后的表达式打进容器日志）；
  4. `FileOutputStream` 写盘，返回路径；任何异常 → 返回 `"error"`。
- `qluntil.executeql(String 路径)`：读文件 → `new ExpressRunner()` → `QLExpressRunStrategy.setForbidInvokeSecurityRiskMethods(true)` → `HashSet` 里 `add(null)` → `setSecureMethods(该集合)` → `execute(表达式, new DefaultContext(), null, false, false)` → 删文件 → 返回 `"success"`；异常 → `"error"`。

于是本题的真实入口是：

```
GET /execute?payload=<base64(QLExpress 表达式)>
```

怎么读这个输出：三点必须记住。

1. 文件名取 `payload.substring(0, 3)`，所以 base64 串长度必须 ≥ 3，且**前三个字符相同的 payload 会互相踩同一个临时文件**；
2. `execute` 的**返回值被 `pop` 掉了**（字节码里 `invokevirtual execute` 之后紧跟 `pop`），响应体只有 `"success"`；
3. 所以"把 flag 读出来放进表达式返回值"这条路根本不存在，必须有副作用 + 带外通道。

### 3.3 第三步：认出沙箱到底设了什么

`setSecureMethods({null})` 是本题的核心。QLExpress 3.3.x 的检查函数是 `QLExpressRunStrategy.assertSecurityRiskMethod(Method m)`，逻辑等价于：

- `forbidInvokeSecurityRiskMethods == false` 或 `m == null` → 直接放行；
- 否则拼 `m.getDeclaringClass().getName() + "." + m.getName()`，若白名单非空则**只允许白名单里的键**，否则走黑名单。

`qluntil` 给的白名单是一个 `HashSet`，里面只有一个 `null`——非空，于是走"白名单模式"，而白名单里唯一的键 `null` 永远匹配不上任何真实方法名。**结论：任何带括号的方法调用都必被拦。**

`NoNetworkSecurityManager` 只覆写了 `checkConnect(String, int)`：目标不是 `localhost` 也不是 `127.` 开头就抛 `SecurityException`。而 `checkPermission(Permission)` 与 `checkPermission(Permission, Object)` 都是空实现（字节码里就是 `return`）。所以文件读写、`exec`、`System.exit` 全放行，只有 JVM 自己发起的非本地连接被掐。

### 3.4 第四步：写 Harness 复刻沙箱，跑九条基线

不能靠"我记得 QLExpress 能这么绕"来写 WP，必须实测。`solve/_test/Harness.java` 把 `executeql` 的配置一字不差地抄了一遍（`ExpressRunner` + `setForbidInvokeSecurityRiskMethods(true)` + `setSecureMethods({null})`），`run.py` 把九条表达式逐条喂进去。本机复跑（JDK 26 + `ql.jar`）的真实输出：

| 编号 | 表达式 | 结果 |
|---|---|---|
| A | `1+1` | `[OK] result=2` |
| B | `"abc".length()` | `[EXC] QLException` |
| C | `new java.io.File("/etc/passwd")` | `[OK] result=\etc\passwd` |
| D | `java.lang.System.out` | `[OK] result=java.io.PrintStream@...` |
| E | `java.lang.Runtime.getRuntime()` | `[EXC] QLException` |
| F | `QLExpressRunStrategy.forbidInvokeSecurityRiskMethods = false` | `[EXC] QLBizException` |
| G | `QLExpressRunStrategy.SECURE_METHOD_LIST = null` | `[EXC] QLBizException` |
| H | `java.lang.System.out.println("hi")` | `[EXC] QLException` |
| I | F 与 H 拼成两句 | `[EXC] QLBizException` |

（C 的 `\etc\passwd` 是 Windows 上的 `File.toString()` 结果，Linux 上会是 `/etc/passwd`；不影响结论。）

怎么读这张表：

- **B/E/H 证明白名单真的生效**，连 `String.length()` 都调不动；
- **C 证明构造器不受这个白名单管**（只有 `ProcessBuilder` / `Socket` / `Desktop` / `PropertyResourceBundle` 四个类在构造器黑名单里）；
- **D 证明静态字段读也不受管**；
- **F/G/I 证明"改静态字段把开关关掉"这条最省事的路走不通**——QLExpress 的赋值目标是变量，`类名.静态字段 = 值` 直接抛 `QLBizException`，不是"被安全策略拒绝"，是语法层面就不支持。

### 3.5 第五步：追加探针，找不过检查的语法点

基线只告诉我"方法调用死了"。真正的问题是：还有哪些语法路径**根本不经过** `assertSecurityRiskMethod`？补了一批探针（同样用 Harness 跑，classpath 补上 `commons-beanutils` / `commons-logging` / `commons-collections`，因为 QLExpress 的属性访问真的会去用它们）：

| 编号 | 表达式 | 真实输出 | 含义 |
|---|---|---|---|
| Q1 | `"abc".bytes.length` | `[OK] result=3` | `getBytes()` 被当 JavaBean 属性读出来 |
| Q2 | `new java.util.Date().time` | `[OK] result=1795082777614` | `getTime()` 被当属性读出来 |
| Q3 | `new java.io.File("/flag").path` | `[OK] result=\flag` | `getPath()` 同上 |
| Q4 | `new java.io.File("/tmp").class` | `[OK] result=null` | `.class` 被特殊处理成 null |
| R4 | `println("hi")` | 打印 `hi`，`[OK] result=null` | 内置函数调用不过检查 |
| R5 | `eval("1+1")` | `[EXC] ... 没有找到eval的定义` | 没有 `eval` 这个内置函数 |
| R2 | `java.lang.System.class.name` | `[EXC] NoSuchFieldException: name` | 对 `Class` 对象做 `.name` 走的是**字段**查找，不是 bean 属性 |

关键发现是 **Q1~Q3**：`对象.名字`（不带括号）走的是 `org.apache.commons.beanutils.PropertyUtils`，直接反射调用 `getXxx()`，**完全不经过 `assertSecurityRiskMethod`**。这是白名单的一整条裂缝。

顺带验证了另一个细节：只用 `ql.jar` 做 classpath 时，`"abc".bytes` 会抛 `java.lang.NoClassDefFoundError: org/apache/commons/beanutils/PropertyUtils`——反过来证明了属性访问确实由 commons-beanutils 承载。

### 3.6 第六步：走不通的地方

有裂缝，但没接上闭环。QLExpress 里"带括号 = 方法调用 = 被拦"，而所有能直达命令执行的入口都是带括号的：`Runtime.getRuntime()`、`ProcessBuilder.start()`、`Class.forName()`、`Method.invoke()`、`ScriptEngine.eval()`。属性访问只能触发**无参 getter**，而 JDK 里没有一个无参 getter 会返回一个"能 exec 的对象"。

## 四、关键知识点

| 概念 | 是什么 | 这题为什么用它 | 以后在哪还会遇到 |
|---|---|---|---|
| QLExpress 沙箱白名单 | `QLExpressRunStrategy.setSecureMethods(Set)`，非空即白名单模式，键为 `类名.方法名` | 这是本题唯一的门槛 | 任何接了表达式引擎的 Java 业务（风控规则、促销规则） |
| 静态字段赋值 | QLExpress 的 `=` 左值只能是变量，不能是 `类.字段` | 决定了"关开关"这条最省事的路直接废掉 | 评估任何表达式注入题的"最短路径"时先试它 |
| 构造器黑名单 | 只挡 `ProcessBuilder`/`Socket`/`Desktop`/`PropertyResourceBundle` | 让 `new java.io.File(...)` 仍然可用 | Java 反序列化 gadget 链的入口判断 |
| JavaBean 属性访问 | `a.b` 交给 commons-beanutils 的 `PropertyUtils` 反射调 getter | 它是绕过 `assertSecurityRiskMethod` 的裂缝 | 所有"过滤了方法名但没过滤属性"的场景 |
| 自定义 SecurityManager | 只覆写 `checkConnect(String,int)`，`checkPermission` 空实现 | 只挡 JVM 自身出网，挡不住子进程 | Java 沙箱题里判断"能不能出网"要先看覆写了哪些 check* |
| fat jar 分层 | `BOOT-INF/classes` + `BOOT-INF/lib` + `JarLauncher` | 决定了解包后能直接 `javap` 业务类 | 所有 Spring Boot 题 |

## 五、踩坑与陷阱

1. **别指望响应回显**。`execute` 的返回值被丢弃，`getql` 只往容器 stdout 打日志。想拿 flag，只能在"带外"上做文章，或者改变程序后续行为。
2. **`substring(0, 3)` 会咬人**。payload 的 base64 短于 3 个字符时 `getql` 直接抛异常返回 `"error"`；两个 payload 前三个 base64 字符相同还会共用一个 `/tmp/xxx.txt`。批量测试时如果不注意，会看到"莫名其妙的 error"。
3. **JDK 版本会改结论**。本题 `Build-Jdk-Spec: 1.8`，而 JDK 24 起 `SecurityManager` 被永久禁用（JEP 486）。我用 JDK 26 跑 Harness 时只复刻了 QLExpress 部分、没装 SecurityManager，所以 3.4/3.5 的表只对"表达式沙箱"成立，不对"出网限制"成立。
4. **不要用 `Set.of()` 之类的不可变集合去模拟**。`qluntil` 用的是可变 `HashSet`，语义上"能被改"和"不能改"是两件事，复刻必须一模一样。
5. **Windows 路径会把结论带偏**。`new java.io.File("/etc/passwd")` 在 Windows 上 `toString()` 出 `\etc\passwd`，看着像"被改写"，其实只是分隔符差异。

## 六、卡点与正解方向

**已确认（有实测支撑）**

- 入口与参数名：`GET /execute?payload=<base64>`；
- 沙箱是"只含 null 的白名单"，所有带括号的方法调用被拦（B/E/H）；
- 构造器可用（C）、静态字段可读（D）、字段赋值不可写（F/G/I）；
- JavaBean 属性访问走 commons-beanutils，**不过安全检查**（Q1~Q3）；
- 内置函数 `println` 可调（R4），但没有 `eval`（R5）。

**卡在哪**

缺一个"从属性读 / 构造器 / 静态字段读"接到"任意命令执行"的最后一跳。属性访问只能触发无参 getter，JDK 标准库里没有能以无参 getter 形式返回 exec 能力的对象；构造器又只剩 4 个黑名单之外的类。

**正解方向（按可信度排序）**

1. **往"带副作用的 setter"走**。既然 getter 不过检查，`对象.属性 = 值` 的 setter 路径同理需要实测（本次没测到这一条就停了）。JDBC / JNDI / 模板类里有大量 setter 带副作用，值得优先扫。
2. **回到黑名单思路**。如果能用属性访问或构造器把 `SECURE_METHOD_LIST` 弄成空，沙箱就退回黑名单模式；而黑名单外至少有 `java.lang.ProcessImpl.start(...)`（包私有静态方法，QLExpress 会 `setAccessible(true)`），这条链在公开资料里被反复提到。难点在于"怎么把静态 private 字段写成空"，本次实测的 `=` 赋值不可用。
3. **出网这关其实很松**。`NoNetworkSecurityManager` 只挡 JVM 自己发起的 `checkConnect(String,int)`，一旦拿到 `exec`，`curl`/`nc` 是独立进程，`SecurityManager` 完全管不到；文件读写更是直接放行（`checkPermission` 空实现）。所以只要拿到 exec，带外就是白送。
4. **flag 位置**按容器常规是 `/flag` 或 `/flag.txt`，`new java.io.FileInputStream("/flag")` 的构造器是允许的——但"能打开"不等于"能读"，读还是得靠方法调用。

## 七、赛场 20 分钟行动清单

1. `unzip` fat jar，`javap -p -c -constants` 三个业务类，画调用链（5 分钟）。
2. 抄 `executeql` 的配置写 Harness，跑 `1+1` 确认环境能跑通（5 分钟）。
3. 一次性打 6 条判别性 payload：`x.length()`、`new java.io.File("/etc/passwd")`、`java.lang.System.out`、`Runtime.getRuntime()`、`类.字段 = 值`、`"a".bytes`（5 分钟）。
4. 依据结果表选方向：白名单全封 → 只在"构造器 / 属性 / 内置函数"里找；黑名单模式 → 直接上 `ProcessImpl.start`（5 分钟）。

> 超过 40 分钟还在"找最后一跳"，先跳题——这类题的性价比极低。

## 八、附件与脚本

- `files/BOOT-INF/classes/`：题目原始业务类（`Main`、`qluntil`、`NoNetworkSecurityManager`、`controller/qlcontroller`），只读，未改动；
- `files/BOOT-INF/lib/`：39 个依赖 jar，`QLExpress-3.3.3.jar` 是核心；
- `solve/_test/Harness.java`：原样复刻 `qluntil.executeql` 沙箱配置的最小可运行程序，`java -cp ql.jar;. Harness <payload文件>`；
- `solve/_test/run.py`：把九条基线写成文件再逐条调 Harness，记录 stdout；
- `solve/_test/exp_A..exp_I_*.txt`：九条基线的表达式原文（文件名即结论，如 `exp_B_method_blocked`）；
- 本次追加的探针（Q1~Q4、R1~R8）放在仓库外的临时目录 `_wp_collect/_qlprobe/`，不污染题目目录。

> 说明：本题 flag 未取得，正文所有输出均为本机复跑所得，不含任何虚构回显。
