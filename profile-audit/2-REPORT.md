# 个人中心与充值模块漏洞检测与安全修复报告

## Web 安全漏洞审计与加固实训

**项目名称：** Flask 用户管理系统 — 个人中心与充值模块  
**漏洞类型：** 权限校验缺失 / 输入验证不足 / CSRF 跨站伪造  
**文档版本：** V1.0 — 终审版  
**生成日期：** 2026 年 7 月  

---

## 目录

1. 项目概述  
   1.1 项目简介  
   1.2 运行环境  
   1.3 新增功能说明  

2. 漏洞风险分析  
   2.1 漏洞成因总述  
   2.2 VULN-PR-01：越权访问用户资料  
   2.3 VULN-PR-02：未授权充值  
   2.4 VULN-PR-03：负金额充值（余额盗取）  
   2.5 VULN-PR-04：大额整数溢出  
   2.6 VULN-PR-05：CSRF 跨站请求伪造充值  
   2.7 VULN-PR-06：硬编码 user_id 致越权  

3. 漏洞验证过程  
   3.1 漏洞版代码关键片段  
   3.2 攻击复现命令与预期结果  
   3.3 Burp Suite 测试过程  

4. 漏洞修复方案  
   4.1 核心修复思想  
   4.2 修复后代码关键片段  
   4.3 修复原理讲解  

5. 修复结果验证  
   5.1 攻击复现回归测试  
   5.2 Burp Suite 回归测试  

6. 安全总结与后续防护建议  

---

## 1. 项目概述

### 1.1 项目简介

本项目是一个基于 Python Flask 框架和 SQLite3 数据库开发的简易用户信息管理系统。系统在已有的登录、注册、用户搜索、头像上传功能基础上，本次新增了**个人中心**和**充值**两大功能模块。个人中心允许用户查看自己的 ID、用户名、邮箱、手机、余额等资料；充值功能允许用户通过表单提交来增加账户余额。

初始版本代码严格遵循"无权限校验、无输入校验"的开发要求编写，导致新增的两个路由存在多处安全缺陷。攻击者可利用这些漏洞越权访问其他用户资料、对任意账户进行充值或扣款、以及发动跨站请求伪造攻击。

本次安全审计围绕六类新增功能衍生的漏洞展开，通过对比漏洞版代码与修复版代码的安全效果，验证登录校验、金额范围校验、CSRF Token 校验等防御手段的有效性。

### 1.2 运行环境

| 项目 | 版本 / 规格 |
|:---|:---|
| 开发语言 | Python 3.10+ |
| Web 框架 | Flask 3.x |
| 数据库 | SQLite3 |
| 模板引擎 | Jinja2 |
| 服务地址 | https://127.0.0.1:5000 |
| 测试工具 | curl、Burp Suite |

### 1.3 新增功能说明

| 路由 | 方法 | 功能 | 参数来源 |
|:---|:---|:---|:---|
| `/profile` | GET | 个人中心展示用户资料 | `user_id` 从 URL 参数获取 |
| `/recharge` | POST | 充值增加用户余额 | `user_id` 和 `amount` 从表单参数获取 |

---

## 2. 漏洞风险分析

### 2.1 漏洞成因总述

本轮新增的六项漏洞可归纳为三类安全缺陷：

**第一类：权限校验缺失（VULN-PR-01、VULN-PR-02）**

新增的 `/profile` 和 `/recharge` 路由均未对请求发起者进行身份认证。路由处理函数中没有任何检查 `session` 中是否存在用户登录信息的逻辑。这意味着攻击者可以不经过登录步骤直接调用这两个接口，未授权地访问系统中的所有用户数据或修改账户余额。

**第二类：输入验证缺失（VULN-PR-03、VULN-PR-04）**

充值接口的 `amount` 参数被直接转换为 `int` 类型后执行 `balance + amount` 运算，全程未对数值的正负性及大小范围做任何校验。攻击者可以通过传入负值从任意账户窃取余额，或通过传入超大数值造成数据库存储异常。

**第三类：请求伪造与硬编码越权（VULN-PR-05、VULN-PR-06）**

充值表单未包含 CSRF Token 隐藏字段，后端也未对 POST 请求进行 CSRF 校验。同时导航栏和首页的"个人中心"链接硬编码为 `user_id=1`（管理员 ID），普通用户点击后直接跳转到管理员个人中心。

---

### 2.2 VULN-PR-01：越权访问用户资料

**【漏洞原理】**

`/profile` 路由直接从 URL 参数中获取 `user_id` 后执行数据库查询，未检查当前请求是否来自已登录用户。攻击者无需任何凭证即可访问系统中任意用户的个人资料。

**【漏洞代码位置】** `app.py` — `/profile` 路由

```python
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id")     # 从URL获取用户ID
    if not user_id:
        return "缺少 user_id 参数", 400
    # ── 缺少登录状态检查 ──
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, balance FROM users WHERE id=?", (user_id,))
    row = c.fetchone()                        # 直接查询并返回数据
    ...
```

**【攻击方式】**

```bash
# 未登录状态下直接查看管理员资料
curl http://127.0.0.1:5000/profile?user_id=1

# 枚举所有用户的 user_id 即可获取全部用户信息
curl http://127.0.0.1:5000/profile?user_id=2   # 查看 alice
curl http://127.0.0.1:5000/profile?user_id=3   # 查看其他注册用户
```

**【风险等级】** ⛔ **高危** — CVSS 3.1 Score: 7.5（High）

攻击者可获取系统中的全部用户资料（用户名、邮箱、手机号、余额），造成大规模用户隐私数据泄露。

---

### 2.3 VULN-PR-02：未授权充值

**【漏洞原理】**

`/recharge` 路由接受表单提交的 `user_id` 和 `amount` 后直接执行余额更新操作，未校验请求发起者是否为已登录用户。任何人只要知道充值接口的 URL 即可对任意用户进行余额修改。

**【漏洞代码位置】** `app.py` — `/recharge` 路由

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id")
    amount = request.form.get("amount")
    # ── 缺少登录状态检查 ──
    # ── 缺少 CSRF Token 校验 ──
    ...
    c.execute("SELECT balance FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    current_balance = row[0]
    new_balance = current_balance + int(amount)   # 直接运算并更新
    c.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, user_id))
    ...
```

**【攻击方式】**

```bash
# 直接发送 POST 请求给任意用户充值，无需登录
curl -d "user_id=1&amount=10000" http://127.0.0.1:5000/recharge
curl -d "user_id=2&amount=-99999" http://127.0.0.1:5000/recharge   # 扣款
```

**【风险等级】** ⛔ **高危** — CVSS 3.1 Score: 8.2（High）

攻击者可任意修改系统中所有用户的余额数据，破坏财务数据完整性。结合负金额使用可直接盗取用户余额。

---

### 2.4 VULN-PR-03：负金额充值（余额盗取）

**【漏洞原理】**

`amount` 参数在代码中被直接转换为整数并参与余额运算，未对数值的正负性做任何限制。攻击者可以传入负数实现从目标账户扣减余额的效果，等同于余额盗取。

**【漏洞代码位置】** `app.py` — `/recharge` 路由第 5-6 行

```python
new_balance = current_balance + int(amount)
# ── 未校验 amount 的正负性 ──
c.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, user_id))
```

**【攻击方式】**

```bash
# 将 admin 余额从 99999 扣减为 -0
curl -d "user_id=1&amount=-99999" http://127.0.0.1:5000/recharge
# 将 alice 余额清零
curl -d "user_id=2&amount=-100" http://127.0.0.1:5000/recharge
```

**【风险等级】** ⛔ **高危** — CVSS 3.1 Score: 7.8（High）

攻击者可清空或窃取任意用户的账户余额，完全破坏系统的财务数据完整性。

---

### 2.5 VULN-PR-04：大额整数溢出

**【漏洞原理】**

`amount` 参数直接调用 `int()` 进行类型转换，未对数值大小做任何限制。Python 虽然支持大整数，但 SQLite 的 INTEGER 字段有存储上限，且超大数值可能导致数据库行为异常。

**【漏洞代码位置】** `app.py` — `/recharge` 路由

```python
amount = request.form.get("amount")
...
new_balance = current_balance + int(amount)   # 无大小范围校验
```

**【攻击方式】**

```bash
# 传入超长数值
curl -d "user_id=1&amount=999999999999999999999999999999999999" http://127.0.0.1:5000/recharge
```

**【风险等级】** ⚠️ **中危** — CVSS 3.1 Score: 4.9（Medium）

可能导致数据库字段溢出或应用程序异常崩溃。

---

### 2.6 VULN-PR-05：CSRF 跨站请求伪造充值

**【漏洞原理】**

充值表单中没有包含 CSRF Token 隐藏字段，后端处理 POST 请求时也未调用 `validate_csrf_token()` 函数进行校验。攻击者可以构造恶意 HTML 页面，诱导已登录用户的浏览器自动提交充值请求。

**【漏洞代码位置】** `profile.html` 第 18-24 行 & `app.py` 第 3-6 行

```html
<form method="POST" action="/recharge" class="form">
    <input type="hidden" name="user_id" value="{{ user.id }}">
    <!-- ── 缺少 CSRF Token 隐藏字段 ── -->
```

**【攻击方式】**

攻击者构造以下恶意页面，诱导已登录用户访问：

```html
<html>
<body>
<form action="https://target.com/recharge" method="POST" id="f">
    <input type="hidden" name="user_id" value="1">
    <input type="hidden" name="amount" value="-99999">
</form>
<script>document.getElementById('f').submit();</script>
</body>
</html>
```

**【风险等级】** ⚠️ **中危** — CVSS 3.1 Score: 6.5（Medium）

已登录用户在不知情的情况下被强制执行充值或扣款操作。

---

### 2.7 VULN-PR-06：硬编码 user_id 致越权

**【漏洞原理】**

导航栏 `base.html` 和首页 `index.html` 中的"个人中心"链接直接写死了 `user_id=1`（对应 admin 管理员）。所有用户点击"个人中心"都默认跳转到管理员页面，而非自己的个人中心。

**【漏洞代码位置】** `base.html` 第 5 行 & `index.html` 第 6 行

```html
<a href="/profile?user_id=1">个人中心</a>   <!-- 硬编码 admin 的 ID -->
```

**【风险等级】** 🔵 **低危** — CVSS 3.1 Score: 3.5（Low）

普通用户无法通过正常导航跳转到自己的个人中心；结合 VULN-PR-01，未登录用户也可直接访问管理员页面。

---

## 3. 漏洞验证过程

### 3.1 漏洞版代码关键片段

以下代码取自漏洞版 app.py 中新增的两个路由，全部六类漏洞均集中于此。

**个人中心路由（完整漏洞代码）：**

```python
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id")
    # 漏洞1：无登录校验 → 任何人都可查看任意用户资料
    # 漏洞6：user_id 可被枚举 → 遍历1,2,3...获取全量用户数据
    if not user_id:
        return "缺少 user_id 参数", 400
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, balance FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return "用户不存在", 404
    user_data = {
        "id": row[0], "username": row[1], "email": row[2],
        "phone": row[3], "balance": row[4]
    }
    return render_template("profile.html", user=user_data)
```

**充值路由（完整漏洞代码）：**

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id")
    amount = request.form.get("amount")
    # 漏洞2：无登录校验 → 未授权充值
    # 漏洞3：amount 无正负校验 → 传入负数扣减余额
    # 漏洞4：amount 无范围校验 → 传入超大数值
    # 漏洞5：无 CSRF Token 校验 → 跨站伪造请求
    if not user_id or not amount:
        return "缺少参数", 400
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return "用户不存在", 404
    current_balance = row[0]
    new_balance = current_balance + int(amount)   # 核心风险运算
    c.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, user_id))
    conn.commit()
    conn.close()
    return redirect(f"/profile?user_id={user_id}")
```

### 3.2 攻击复现命令与预期结果

| 漏洞编号 | 攻击命令 | 预期结果 |
|:---|:---|:---|
| PR-01 | `curl http://127.0.0.1:5000/profile?user_id=1` | 返回 admin 的完整资料（邮箱、手机、余额） |
| PR-01 | `curl http://127.0.0.1:5000/profile?user_id=2` | 返回 alice 的完整资料 |
| PR-02 | `curl -d "user_id=1&amount=50000" http://127.0.0.1:5000/recharge` | admin 余额增加 50000 |
| PR-03 | `curl -d "user_id=1&amount=-99999" http://127.0.0.1:5000/recharge` | admin 余额被扣减至接近零 |
| PR-04 | `curl -d "user_id=1&amount=999999999999" http://127.0.0.1:5000/recharge` | 数据库写入超大数值 |
| PR-05 | 诱导用户访问恶意 HTML 页面 | 用户浏览器自动执行充值请求 |
| PR-06 | 点击导航栏"个人中心"链接 | 普通用户跳转到 admin 的个人中心 |

### 3.3 Burp Suite 测试过程

**测试步骤：**

1. 启动 Burp Suite，配置浏览器代理为 127.0.0.1:8080。
2. 在浏览器中访问 `/profile?user_id=1` 页面并查看响应内容。
3. 将请求发送到 Repeater，修改 `user_id` 参数值为 2、3、4 等依次发送，观察是否返回不同用户的数据。
4. 拦截 `/recharge` 的 POST 请求，在 Repeater 中尝试以下参数组合：

| 测试编号 | 修改内容 | 测试目的 | 预期结果 |
|:---|:---|:---|:---|
| ① | `user_id=1&amount=1000` | 正常充值 | 余额增加 1000 |
| ② | `user_id=1&amount=-99999` | 负金额扣款 | 余额被扣减 |
| ③ | `user_id=1&amount=999999999999` | 超大金额 | 数据库写入异常值 |
| ④ | 删除 `Cookie` 请求头后发送 | 未授权访问 | 仍然充值成功 |

---

## 4. 漏洞修复方案

### 4.1 核心修复思想

本次修复在同一份代码中实施**三道防线**，分别对应三类安全缺陷：

| 防线 | 对应漏洞 | 技术手段 |
|:---|:---|:---|
| **第一道：身份认证** | PR-01、PR-02 | 在路由处理函数开头检查 `session` 登录状态 |
| **第二道：输入校验** | PR-03、PR-04 | 对 `amount` 进行正负性 + 范围双重校验 |
| **第三道：请求防伪** | PR-05 | 前后端配合实施 CSRF Token 校验 |
| **第四道：链接修正** | PR-06 | 导航栏和首页链接去掉硬编码参数 |

### 4.2 修复后代码关键片段

**修复后的个人中心路由：**

```python
@app.route("/profile")
def profile():
    # 第一道防线：要求用户必须登录
    if "username" not in session:
        return redirect("/login")

    user_id = request.args.get("user_id")

    # 第四道防线：未传 user_id 时自动解析当前登录用户
    if not user_id:
        username = session.get("username")
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            user_id = str(row[0])
        else:
            return "用户不存在", 404

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, balance FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    # ... 返回模板渲染
```

**修复后的充值路由：**

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    # 第一道防线：要求用户必须登录
    if "username" not in session:
        return redirect("/login")

    # 第三道防线：CSRF Token 校验
    if not validate_csrf_token():
        return render_template("login.html", error="会话已过期，请刷新页面后重试！")

    user_id = request.form.get("user_id")
    amount = request.form.get("amount")

    if not user_id or not amount:
        return "缺少参数", 400

    # 第二道防线：金额格式校验
    try:
        amount_val = int(amount)
    except ValueError:
        return "金额格式错误", 400

    # 第二道防线：正负校验 + 范围校验
    if amount_val <= 0:
        return "金额必须为正整数", 400
    if amount_val > 1000000:
        return "单次充值金额不能超过 1000000", 400

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return "用户不存在", 404

    current_balance = row[0]
    new_balance = current_balance + amount_val
    c.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, user_id))
    conn.commit()
    conn.close()
    return redirect(f"/profile?user_id={user_id}")
```

**修复后的个人中心表单（profile.html）：**

```html
<form method="POST" action="/recharge" class="form">
    <!-- 第三道防线：添加 CSRF Token -->
    <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
    <input type="hidden" name="user_id" value="{{ user.id }}">
    <div class="form-group">
        <label for="amount">充值金额</label>
        <input type="number" id="amount" name="amount" class="form-input"
               placeholder="请输入金额" min="1" required>
    </div>
    <button type="submit" class="btn btn-primary">充值</button>
</form>
```

**修复后的导航栏链接（base.html）：**

```html
<!-- 第四道防线：去除硬编码 user_id=1 -->
<a href="/profile" class="navbar-link">个人中心</a>
```

### 4.3 修复原理讲解

**第一道防线 — 身份认证的原理：**

Flask 的 `session` 对象基于加密 Cookie 实现。当用户登录成功时，代码将用户名写入 `session["username"]`。在所有需要保护的路由中，首先检查 `session` 中是否存在 `username` 键。如果不存在，说明当前请求未经过登录认证，直接重定向到登录页面。这一机制可以防御未授权访问（VULN-PR-01/VULN-PR-02）。

**第二道防线 — 金额校验的原理：**

对 `amount` 参数实施三层检查：
1. **类型检查**：使用 `try/except` 包裹 `int()` 转换，捕获非数字输入
2. **正负检查**：`if amount_val <= 0` 拦截零和负数
3. **范围检查**：`if amount_val > 1000000` 拦截超大金额

这三层检查可以在用户提交恶意金额时直接返回错误响应，拒绝继续执行数据库操作。

**第三道防线 — CSRF Token 校验的原理：**

在服务端，`generate_csrf_token()` 函数为每个会话生成一个 256 位的随机 Token 并存储在 `session` 中。该 Token 通过 Jinja2 全局变量注入到所有模板中，表单渲染时包含一个隐藏的 `_csrf_token` 字段。当表单提交时，后端 `validate_csrf_token()` 函数从 `session` 中取出 Token 并与表单提交的 Token 进行常量时间比较。由于攻击者的恶意页面无法获取目标用户 `session` 中存储的 Token，因此构造的跨站请求会被服务器拒绝。

**第四道防线 — 链接修正的原理：**

将导航栏和首页的"个人中心"链接从 `/profile?user_id=1` 改为 `/profile`（无参数）。在 `profile` 路由中，当未收到 `user_id` 参数时，通过当前登录用户的用户名从数据库查询其对应的 ID。这样每个用户点击"个人中心"都会跳转到自己的资料页面。

---

## 5. 修复结果验证

### 5.1 攻击复现回归测试

在启动修复版服务后，重新执行全部攻击复现命令，结果如下：

| 测试项目 | 漏洞版结果 | 修复版结果 | 结论 |
|:---|:---|:---|:---|
| 未登录访问 `/profile?user_id=1` | ✅ 返回 admin 资料 | ❌ 302 跳转到登录页 | 登录校验生效 |
| 未登录调用 `/recharge` | ✅ 余额被修改 | ❌ 302 跳转到登录页 | 登录校验生效 |
| 传入 `amount=-500` | ✅ 余额被扣减 | ❌ 返回"金额必须为正整数" | 正负校验生效 |
| 传入超大金额 | ✅ 余额被写入 | ❌ 返回"金额不能超过 1000000" | 范围校验生效 |
| 提交无 CSRF Token 的请求 | ✅ 充值成功 | ❌ 返回"会话已过期" | CSRF 校验生效 |
| 点击"个人中心"导航链接 | ✅ 跳转到 admin 页面 | ❌ 跳转到当前用户页面 | 链接修正生效 |
| 正常充值 100 元 | ✅ 余额增加 100 | ✅ 余额增加 100 | 业务功能正常 |

### 5.2 Burp Suite 回归测试

| 测试编号 | 漏洞版结果 | 修复版结果 |
|:---|:---|:---|
| ① 正常充值 | 余额增加 | 余额正常增加 |
| ② 负金额扣款 | 余额被扣减 | 返回"金额必须为正整数" |
| ③ 超大金额 | 写入异常值 | 返回"金额不能超过 1000000" |
| ④ 删除 Cookie 请求 | 仍然成功 | 302 跳转到登录页 |

---

## 6. 安全总结与后续防护建议

### 安全总结

本次个人中心与充值模块漏洞审计与修复实训得出以下结论：

**第一，所有涉及敏感操作的接口必须实施身份认证。** 无论是展示用户资料还是修改账户余额，路由处理函数在执行业务逻辑前必须先确认请求来自已登录的用户。缺少登录校验是最常见也最危险的安全遗漏之一。

**第二，用户输入的数值参数必须做正负性和范围校验。** 与财务相关的操作（充值、转账、下单等）尤其需要注意——即使是业务上只允许正数的场景，如果代码不做检查，攻击者传入负数即可实现反向操作。

**第三，CSRF 防护必须贯穿表单提交的始终。** 前端表单需要包含 CSRF Token 隐藏字段，后端 POST 请求处理时需要进行 Token 校验，两者缺一不可。CSRF 漏洞的修复成本很低，但被利用后造成的后果可能是毁灭性的。

### 后续防护建议

| 优先级 | 建议措施 | 说明 |
|:---|:---|:---|
| P0 | 全量路由审计 | 检查系统中所有 POST/GET 路由是否缺失登录校验 |
| P0 | 金额操作事务化 | 充值操作应使用数据库事务，防止并发写入脏数据 |
| P1 | 操作日志记录 | 对充值等敏感操作记录日志（谁、什么时间、操作了什么） |
| P1 | 充值上限限制 | 单日累计充值上限，防止攻击者在短时间内多次利用 |
| P2 | 余额变动通知 | 余额发生变动时通过邮件或站内信通知用户 |
| P2 | 二次确认弹窗 | 充值金额较大时弹出二次确认对话框 |

---

*报告生成时间：2026年7月 | 测试工具：curl、Burp Suite | 修复方式：登录校验 + 金额校验 + CSRF Token + 链接修正*
