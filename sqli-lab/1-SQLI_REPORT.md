# SQL注入漏洞检测与安全修复报告

## Web安全漏洞审计与加固实训

**项目名称：** Flask用户信息管理系统  
**漏洞类型：** SQL注入（SQL Injection）  
**文档版本：** V1.0  
**生成日期：** 2026年7月

---

## 目录

1. 项目概述  
   1.1 项目简介  
   1.2 运行环境  
2. 漏洞风险分析  
   2.1 漏洞成因分析  
   2.2 POC-1：UNION注入分析  
   2.3 POC-2：OR万能注入分析  
   2.4 POC-3：注册页面注入分析  
3. 漏洞验证过程  
   3.1 漏洞版代码关键片段  
   3.2 三组POC执行命令与预期结果  
   3.3 Burp Suite测试过程  
4. 漏洞修复方案  
   4.1 核心修复思想  
   4.2 修复后代码关键片段  
   4.3 修复原理讲解  
5. 修复结果验证  
   5.1 POC回归测试  
   5.2 Burp Suite回归测试  
6. 安全总结与后续防护建议  

---

## 1. 项目概述

### 1.1 项目简介

本项目是一个基于 Python Flask 框架和 SQLite3 数据库开发的简易用户信息管理系统，系统提供用户登录、用户搜索、用户注册三项核心功能。初始版本代码存在严重 SQL 注入漏洞，攻击者可利用搜索接口和注册接口的字符串拼接缺陷，执行恶意的 SQL 语句，获取非授权数据或向数据库中插入恶意数据。

本次安全审计围绕三组标准化的 POC（Proof of Concept）测试用例展开，涵盖 UNION 注入、OR 万能注入、注册页面注入三种典型攻击方式。通过对比漏洞版代码（vulnerable-app.py）与修复版代码（fixed-app.py）的安全效果，验证参数化查询对 SQL 注入的防御能力。

### 1.2 运行环境

| 项目 | 版本 / 规格 |
|------|------------|
| 开发语言 | Python 3.10+ |
| Web 框架 | Flask 3.x |
| 数据库 | SQLite3 |
| 模板引擎 | Jinja2 |
| 服务地址 | http://127.0.0.1:5000 |
| 数据表结构 | users（id, username, email, phone） |
| 测试工具 | curl、Burp Suite |

---

## 2. 漏洞风险分析

### 2.1 漏洞成因分析

SQL 注入漏洞的根源在于**将用户输入的数据直接拼接到 SQL 语句中**，未做任何转义或参数化处理。

在本系统中，搜索路由 `/search` 和注册路由 `/register` 使用 Python 的 f-string 机制将用户提交的 keyword、username 等参数直接嵌入 SQL 模板字符串。由于用户输入的内容可以被自由构造，攻击者可以通过注入单引号（`'`）、注释符（`--`）、UNION 关键字等 SQL 特殊字符，改变原 SQL 语句的语法结构，从而执行非预期的数据库操作。

以搜索路由为例，正常的 SQL 执行逻辑是：

```sql
SELECT id, username, email, phone FROM users WHERE username LIKE '%keyword%' OR email LIKE '%keyword%'
```

如果 keyword 参数被直接拼接且不做过滤，当攻击者输入 `' OR '1'='1` 时，SQL 语句变为：

```sql
SELECT id, username, email, phone FROM users WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
```

此时 `OR '1'='1'` 使 WHERE 子句恒为真，查询返回全部用户数据，造成信息泄露。

### 2.2 POC-1：UNION 注入分析

**注入原理：**

UNION 注入利用 SQL 的 UNION SELECT 子句将自定义查询结果合并到原查询的返回集中。攻击者在 keyword 参数中注入单引号闭合原 LIKE 字符串，追加 UNION SELECT 子句，再用注释符 `--` 屏蔽后续 SQL。

原搜索查询返回 4 列（id, username, email, phone），因此 UNION SELECT 也需要提供 4 个列值，否则 SQLite 会报"列数不匹配"错误。

**拼接后的完整 SQL 语句：**

攻击者输入 keyword 参数（URL 编码后）：
```
' UNION SELECT 1,'inj','inj@x.com','138'--
```

实际拼接后由数据库执行的 SQL：
```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
OR email LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
```

**执行效果：**

数据库返回两条结果集：第一条来自原查询（若无匹配则空），第二条来自 UNION SELECT 注入的自定义数据 `{1, 'inj', 'inj@x.com', '138'}`。页面渲染后会出现攻击者伪造的用户记录。

**安全危害：**

攻击者通过 UNION 注入可以探测数据库的列数、表名、字段名等元信息。在真实的攻击场景中，攻击者可进一步利用 UNION SELECT 读取其他表中的敏感数据，例如管理员密码哈希、用户令牌等。

### 2.3 POC-2：OR 万能注入分析

**注入原理：**

OR 万能注入的核心思路是在 WHERE 子句中注入一个恒真条件，使 WHERE 判断结果永远为 True，从而绕过原有的条件过滤，返回表中全部数据。

**拼接后的完整 SQL 语句：**

攻击者输入 keyword 参数：
```
' OR '1'='1
```

实际拼接后由数据库执行的 SQL：
```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
```

其中 `' OR '1'='1` 中的单引号闭合了第一个 LIKE 的 `%'`，`OR '1'='1` 使条件永远成立，`%'` 闭合了最后一个 LIKE 的语法结构。

**执行效果：**

由于 `'1'='1'` 恒为真，数据库返回 users 表中的全部记录，包括 admin、alice 等所有用户。搜索结果展示所有用户的 ID、用户名、邮箱、手机号。

**安全危害：**

攻击者可遍历系统中全部用户信息，无需知道具体用户名或密码。在登录场景中，OR 注入可被用于绕过身份认证（如 `' OR '1'='1' --` 拼接到登录 SQL 的密码验证处）。

### 2.4 POC-3：注册页面注入分析

**注入原理：**

注册路由将用户提交的 username 参数直接拼接到 INSERT 语句的 VALUES 子句中。攻击者通过在 username 字段中注入单引号和括号，闭合原 VALUES 列表，再用注释符 `--` 屏蔽掉后续的 password、email、phone 参数，从而控制插入到数据库中的数据。

**拼接后的完整 SQL 语句：**

攻击者提交表单，username 参数为：
```
hacker', 'pass', 'h@x.com', '123')--
```

实际拼接后由数据库执行的 SQL：
```sql
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'pass', 'h@x.com', '123')--', 'irrelevant', '', '')
```

username 字段中的 `'` 闭合了原 VALUES 的第一个字符串，`, 'pass', 'h@x.com', '123')` 补全了其他三个字段值，`)` 闭合了整个 VALUES 列表，`--` 将剩余的 `', 'irrelevant', '', '')` 全部注释掉。

**执行效果：**

数据库中成功插入一条新记录：username='hacker', password='pass', email='h@x.com', phone='123'。系统提示"注册成功，请登录"。password 字段的实际值并非用户提交的 "irrelevant"，而是注入字符串中指定的 "pass"。

**安全危害：**

攻击者可以完全控制插入数据库的字段值，无视服务端对表单提交数据的处理逻辑。结合其他漏洞，攻击者可能插入一个具有高权限的账号，或者将恶意数据写入数据库以供后续利用。

---

## 3. 漏洞验证过程

### 3.1 漏洞版代码关键片段

以下代码取自 vulnerable-app.py，两处 SQL 注入漏洞分别位于搜索路由和注册路由。

**搜索路由（第64行）：**

```python
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 漏洞：直接拼接用户输入
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        c.execute(sql)
```

关键字 `keyword` 从 URL 参数直接获取，通过 f-string 嵌入 SQL 模板，未做任何过滤或转义。

**注册路由（第85行）：**

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email    = request.form.get("email", "")
        phone    = request.form.get("phone", "")
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 漏洞：直接拼接用户输入
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        c.execute(sql)
```

username、password、email、phone 四个字段均通过 f-string 拼接，每一个都是可注入点。

### 3.2 三组POC执行命令与预期结果

**POC-1：UNION 注入**

前置步骤——登录获取 session cookie：
```bash
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt
```

注入测试：
```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--" -b /tmp/cookies.txt
```

预期结果：页面响应中包含字符串 "inj"，表示 UNION SELECT 注入的自定义数据成功渲染在页面上。

**POC-2：OR 万能注入**

```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271" -b /tmp/cookies.txt
```

预期结果：页面返回 admin、alice 等全部用户数据，表格中展示所有用户 ID、用户名、邮箱、手机号。

**POC-3：注册页面注入**

```bash
curl http://127.0.0.1:5000/register -d "username=hacker', 'pass', 'h@x.com', '123')--&password=irrelevant"
```

预期结果：页面提示"注册成功，请登录"。使用注入写入的 hacker/pass 组合可登录系统。

### 3.3 Burp Suite 测试过程

1. 启动 Burp Suite，配置浏览器代理为 127.0.0.1:8080。
2. 登录系统后，在浏览器的搜索框中输入 "admin" 并提交搜索。
3. 在 Burp Suite 的 Proxy → HTTP history 中找到该 GET 请求，右键发送到 Repeater。
4. 在 Repeater 面板中，修改 keyword 参数值，依次测试以下注入语句：

| 序号 | 测试语句 | 说明 |
|------|---------|------|
| ① | `admin' OR '1'='1` | OR 万能注入，预期返回全部用户 |
| ② | `' UNION SELECT 1,2,3,4--` | UNION 探测列数，预期页面出现 1,2,3,4 |
| ③ | `' UNION SELECT 1,username,email,phone FROM users--` | UNION 获取真实数据，预期返回 admin 信息 |

5. 点击 Send，观察 Response 中返回的数据是否异常。若返回的数据中包含非预期的内容（如所有用户、数字序列、自定义字符串），则确认 SQL 注入漏洞存在。

---

## 4. 漏洞修复方案

### 4.1 核心修复思想

修复 SQL 注入漏洞的根本方法是不再使用字符串拼接来构建 SQL 语句，而是采用**参数化查询**机制。在 Python 的 sqlite3 模块中，参数化查询使用 `?` 作为占位符，将用户输入的参数与 SQL 模板分离。数据库驱动在底层会自动对参数中的特殊字符（单引号、双引号、反斜杠等）进行转义处理，确保用户输入仅作为普通字符串值传递，不会被解析为 SQL 语法的一部分。

### 4.2 修复后代码关键片段

**修复后的搜索路由：**

```python
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 修复：使用 ? 占位符，杜绝字符串拼接
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        param = f"%{keyword}%"
        c.execute(sql, (param, param))
        for row in c.fetchall():
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
        conn.close()
```

核心改动：`f"SELECT ... LIKE '%{keyword}%'"` 替换为 `"SELECT ... LIKE ?"`，参数通过 `execute()` 的第二个参数以元组形式传入。

**修复后的注册路由：**

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email    = request.form.get("email", "")
        phone    = request.form.get("phone", "")
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 修复：使用 ? 占位符，杜绝字符串拼接
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        c.execute(sql, (username, password, email, phone))
        conn.commit()
        conn.close()
```

核心改动：`f"INSERT ... VALUES ('{username}', ...)"` 替换为 `"INSERT ... VALUES (?, ?, ?, ?)"`，四个参数通过元组传入。

### 4.3 修复原理讲解

参数化查询之所以能够防御 SQL 注入，原理如下：

第一，**语法解析与参数值分离**。数据库在接收到带有 `?` 占位符的 SQL 语句时，会先对 SQL 模板进行语法编译和解析，确定语句的完整语义结构。此时占位符的位置被预留，但尚未填充具体值。随后，数据库引擎将参数值以"数据"而非"代码"的形式填入占位符位置。因此，即使用户输入中包含单引号、分号、注释符、UNION 等 SQL 关键字，它们在语义层面只是普通的字符串内容，不会改变已解析的 SQL 语法结构。

第二，**自动转义处理**。sqlite3 模块在将参数传递给数据库引擎时，会自动对特殊字符进行转义。例如，用户输入 `' OR '1'='1`，其中的单引号会被自动转义为 `''`，在 SQL 语义中表示字面量的单引号字符，而不是字符串边界符。因此 `LIKE '%'' OR ''1''=''1%'` 只是匹配一个包含 `' OR '1'='1` 文本的字符串，而不会触发 OR 条件判断。

第三，**杜绝二次拼接**。修复后的代码确保用户输入的原始数据从表单获取后，直接通过参数传递到 `execute()` 函数，中间不经过任何字符串拼接操作。这从根本上消除了注入的可能。

---

## 5. 修复结果验证

### 5.1 POC 回归测试

在启动修复版服务（fixed-app.py）后，重新执行三组 POC 命令，结果如下：

| 测试项目 | 漏洞版结果 | 修复版结果 | 结论 |
|---------|-----------|-----------|------|
| POC-1 UNION 注入 | 页面包含 "inj" 字符串 | 页面提示"无搜索结果"，"inj" 不出现 | UNION 注入失效 |
| POC-2 OR 万能注入 | 展示 admin、alice 等全部用户 | 页面提示"无搜索结果"，无用户数据返回 | OR 注入失效 |
| POC-3 注册注入 | 注册成功，hacker 用户写入数据库 | 注册失败，提示"用户名可能已存在"或 SQL 约束错误 | 注入语句被参数化，括号和注释符被转义 |

以上测试结果表明，三组 POC 的注入 Payload 在参数化查询的保护下全部失效，用户输入的特殊字符被安全地作为普通字符串处理。

### 5.2 Burp Suite 回归测试

在 Burp Suite Repeater 中重新发送三个测试语句：

① `admin' OR '1'='1` → 页面返回"无搜索结果"

② `' UNION SELECT 1,2,3,4--` → 页面返回"无搜索结果"，未出现数字序列

③ `' UNION SELECT 1,username,email,phone FROM users--` → 页面返回"无搜索结果"

Burp Suite 测试确认三条注入语句在修复版中均无法执行，全部返回正常的无结果状态。

---

## 6. 安全总结与后续防护建议

### 安全总结

本次 SQL 注入漏洞审计与修复实训得出以下结论：

1. **字符串拼接是 SQL 注入的根本原因**。将用户输入的数据直接拼接到 SQL 语句中，使得攻击者可以通过构造特殊字符改变 SQL 的语法结构，这是所有 SQL 注入漏洞的共同特征。

2. **参数化查询是防御 SQL 注入的第一道防线**。使用 `?` 占位符将 SQL 模板与数据分离，数据库引擎不再将用户输入解析为 SQL 语法，从根本上消除了注入的可能性。该方法实施成本低、兼容性好、对业务逻辑无影响。

3. **搜索接口和注册接口是注入的高发区域**。LIKE 模糊查询和 INSERT 语句的 VALUES 子句需要拼接用户输入，如果未使用参数化查询，极易成为注入点。

### 后续防护建议

| 优先级 | 建议措施 | 说明 |
|--------|---------|------|
| P0 | 禁止直接拼接 SQL | 所有数据库操作强制使用参数化查询或 ORM 框架 |
| P0 | 关闭 debug 模式 | 生产环境设置 `debug=False`，防止错误信息泄露数据库结构 |
| P1 | 最小权限原则 | 数据库连接账户仅授予必要权限（如禁止 DROP、TRUNCATE） |
| P1 | 输入内容过滤 | 对用户输入进行长度校验和特殊字符过滤，作为深度防御 |
| P2 | 部署 WAF | Web 应用防火墙可检测并拦截常见的 SQL 注入 Payload |
| P2 | 定期安全审计 | 通过代码审计和渗透测试定期检查 SQL 注入等 Web 漏洞 |

---

*报告生成时间：2026年7月 | 测试工具：curl、Burp Suite | 修复方式：sqlite3 参数化查询*
