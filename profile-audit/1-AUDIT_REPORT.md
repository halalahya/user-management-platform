# 个人中心与充值模块安全审计报告

**审计范围：** Flask用户管理系统 — 本轮新增的 /profile 路由、/recharge 路由、profile.html 模板、base.html 导航栏、index.html 快捷入口  
**审计日期：** 2026年7月  
**漏洞数量：** 共发现 **6 项安全漏洞**

---

## 漏洞总览

| 编号 | 漏洞名称 | 触发位置 | 风险等级 |
|------|---------|---------|---------|
| VULN-PR-01 | 越权访问用户资料（无登录校验） | `/profile` GET 路由 | 高危 |
| VULN-PR-02 | 未授权充值（无登录校验） | `/recharge` POST 路由 | 高危 |
| VULN-PR-03 | 负金额充值（余额盗取） | `/recharge` amount 参数 | 高危 |
| VULN-PR-04 | 大额整数溢出 | `/recharge` amount 参数 | 中危 |
| VULN-PR-05 | CSRF 跨站请求伪造充值 | `/recharge` 缺少 Token 校验 | 中危 |
| VULN-PR-06 | 硬编码 user_id 致越权 | `base.html` 导航栏链接 | 低危 |

---

## 漏洞详情

### VULN-PR-01：越权访问用户资料

**触发位置：** `app.py` 第 356-378 行 `/profile` 路由

**漏洞代码：**
```python
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id")
    if not user_id:
        return "缺少 user_id 参数", 400
    # 未校验用户是否登录
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, balance FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    ...
```

**复现步骤：**
```bash
# 未登录状态下直接访问任意用户资料
curl http://127.0.0.1:5000/profile?user_id=1   # 查看 admin
curl http://127.0.0.1:5000/profile?user_id=2   # 查看 alice
```

**风险说明：** 无需任何身份认证即可查看全部用户的邮箱、手机、余额等敏感信息，属于严重信息泄露。

### VULN-PR-02：未授权充值

**触发位置：** `app.py` 第 384-404 行 `/recharge` 路由

**漏洞代码：**
```python
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id")
    amount = request.form.get("amount")
    # 未校验用户是否登录
    conn = sqlite3.connect("data/users.db")
    ...
```

**复现步骤：**
```bash
# 无需登录，直接修改任意用户余额
curl -d "user_id=1&amount=10000" http://127.0.0.1:5000/recharge
```

**风险说明：** 任意未认证用户可通过 POST 请求修改系统中任意用户的余额。

### VULN-PR-03：负金额充值（余额盗取）

**触发位置：** `app.py` 第 400 行 `new_balance = current_balance + int(amount)`

**漏洞代码：**
```python
new_balance = current_balance + int(amount)
c.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, user_id))
```

**复现步骤：**
```bash
# 传入负值即可扣减余额
curl -d "user_id=1&amount=-99999" http://127.0.0.1:5000/recharge
```

**风险说明：** 攻击者可清空任意用户余额，甚至将余额扣为负数，完全破坏系统的财务数据完整性。

### VULN-PR-04：大额整数溢出

**触发位置：** `app.py` 第 387 行 `amount = request.form.get("amount")` 及第 400 行 `int(amount)`

**漏洞代码：**
```python
amount = request.form.get("amount")
...
new_balance = current_balance + int(amount)
```

**复现步骤：**
```bash
curl -d "user_id=1&amount=999999999999999999999999999999999999" http://127.0.0.1:5000/recharge
```

**风险说明：** Python 大整数可能导致内存异常，或超出数据库字段存储范围（SQLite INTEGER 有上限），造成数据损坏。

### VULN-PR-05：CSRF 跨站请求伪造充值

**触发位置：** `app.py` 第 384 行 `/recharge` 路由 & `profile.html` 第 18-24 行充值表单

**漏洞代码：**
```html
<form method="POST" action="/recharge" class="form">
    <input type="hidden" name="user_id" value="{{ user.id }}">
    <!-- 缺少 CSRF Token 隐藏字段 -->
```

**复现步骤：** 攻击者构造恶意 HTML 页面，诱导已登录用户访问，自动提交充值请求。

**风险说明：** 已登录用户在不知情的情况下执行非意愿的充值操作（正负值均可能）。

### VULN-PR-06：硬编码 user_id 致越权

**触发位置：** `base.html` 第 15 行 & `index.html` 第 18 行

**漏洞代码：**
```html
<a href="/profile?user_id=1" class="navbar-link">个人中心</a>
```

**风险说明：** 导航栏固定指向 user_id=1（admin），普通用户点击直接跳转到管理员个人中心。结合无登录校验，形成信息泄露。

---

## 审计结论

本轮新增的个人中心与充值功能共发现 6 项安全漏洞。核心问题集中在：**无身份认证**（任何人都可使用接口）、**无输入校验**（负金额/超大金额可被接受）、**无 CSRF Token**（跨站请求伪造）、**无权限管控**（任意用户间数据互通）。
