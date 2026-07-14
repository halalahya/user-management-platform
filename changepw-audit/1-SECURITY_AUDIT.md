# 修改密码功能安全审计报告

**审计模块：** `/change-password` 路由 & `profile.html` 修改密码表单  
**漏洞数量：** 共发现 **5 项安全漏洞**

---

## 漏洞总览

| 编号 | 漏洞名称 | 触发位置 | 风险等级 |
|------|---------|---------|---------|
| VULN-CP-01 | 无原密码校验（可直接修改任意用户密码） | `app.py` 第 492-498 行 | 高危 |
| VULN-CP-02 | 隐藏字段可篡改（已登录用户可修改他人密码） | `profile.html` 第 28 行 | 高危 |
| VULN-CP-03 | 无 CSRF Token 校验（跨站请求伪造修改密码） | `app.py` 第 487 行 | 中危 |
| VULN-CP-04 | 无密码强度校验（弱密码可被设置） | `app.py` 第 493 行 | 中危 |
| VULN-CP-05 | 确认密码仅前端校验（后端未验证一致性） | `app.py` 第 493 行 | 低危 |

---

## 漏洞详情

### VULN-CP-01：无原密码校验

**【漏洞原理】**

修改密码接口未要求用户输入原密码进行身份验证。攻击者只要获得了已登录用户的会话（如通过 XSS 或物理接触），即可直接修改该账号的密码。

**【漏洞代码】**

```python
username = request.form.get("username")
new_password = request.form.get("new_password")
# 直接执行修改，未校验原密码
if username in USERS:
    USERS[username]["password"] = generate_password_hash(new_password)
```

**【风险等级】** 高危 — CVSS 3.1 Score: 8.2

**【修复方式】** 要求用户输入原密码，使用 `check_password_hash()` 验证通过后才执行修改。

**【修复代码】**

```python
username = request.form.get("username")
old_password = request.form.get("old_password")
new_password = request.form.get("new_password")

if not username or not old_password or not new_password:
    return "缺少参数", 400

if username not in USERS or not check_password_hash(USERS[username]["password"], old_password):
    return "原密码错误", 403
```

---

### VULN-CP-02：隐藏字段可篡改

**【漏洞原理】**

表单中的 `username` 通过隐藏字段传递，页面源码中直接暴露。已登录用户可通过浏览器开发者工具或 curl 修改该字段的值，将密码修改为目标用户的密码。

**【漏洞代码】**

```html
<!-- profile.html 第 28 行 -->
<input type="hidden" name="username" value="admin">
```

攻击者只需将 `value="admin"` 改为 `value="alice"` 即可修改 alice 的密码。

**【攻击验证】**

```bash
# 以 admin 身份登录后，修改 alice 的密码
curl -X POST -d "username=alice&new_password=123456" https://127.0.0.1:5000/change-password
```

**【风险等级】** 高危 — CVSS 3.1 Score: 7.5

**【修复方式】** 不从表单获取 username，而是从当前 session 中读取登录用户名，杜绝隐藏字段篡改。

**【修复代码】**

```python
# 从 session 获取当前登录用户，不从表单获取
username = session.get("username")
```

---

### VULN-CP-03：无 CSRF Token 校验

**【漏洞原理】**

修改密码接口未校验 CSRF Token，攻击者可构造恶意页面诱导已登录用户访问，浏览器自动提交表单实现密码篡改。

**【漏洞代码】**

```python
@app.route("/change-password", methods=["POST"])
def change_password():
    # 缺少 validate_csrf_token() 调用
    ...
```

**【风险等级】** 中危 — CVSS 3.1 Score: 6.5

**【修复方式】** 调用 `validate_csrf_token()` 进行校验，表单中增加 CSRF Token 隐藏字段。

**【修复代码】**

```python
if not validate_csrf_token():
    return render_template("login.html", error="会话已过期，请刷新页面后重试！")
```

---

### VULN-CP-04：无密码强度校验

**【漏洞原理】**

后端未对 `new_password` 的长度和复杂度做任何校验，空密码或单字符密码也可能被接受。弱密码极易被暴力破解。

**【漏洞代码】**

```python
new_password = request.form.get("new_password")
if not username or not new_password:
    return "缺少参数", 400
# 没有密码长度和复杂度校验
```

**【风险等级】** 中危 — CVSS 3.1 Score: 5.3

**【修复方式】** 增加密码最小长度校验和复杂度要求。

**【修复代码】**

```python
if len(new_password) < 6:
    return "密码长度不能少于6位", 400
if len(new_password) > 128:
    return "密码长度不能超过128位", 400
```

---

### VULN-CP-05：确认密码仅前端校验

**【漏洞原理】**

`profile.html` 的修改密码表单包含"确认密码"输入框，但后端从未校验 `new_password` 和 `confirm_password` 是否一致。前端校验可被绕过（禁用 JavaScript 或直接发送 curl 请求）。

**【漏洞代码】**

```python
# 只接收了 new_password，未接收 confirm_password 做比对
new_password = request.form.get("new_password")
```

**【风险等级】** 低危 — CVSS 3.1 Score: 3.3

**【修复方式】** 后端接收并比对 `confirm_password` 参数。

**【修复代码】**

```python
confirm_password = request.form.get("confirm_password")
if new_password != confirm_password:
    return "两次输入的密码不一致", 400
```

---

## 修复前后对比总表

| 安全维度 | 漏洞版 | 修复版 |
|---------|-------|-------|
| 原密码校验 | 无，可直接修改 | 需验证原密码 |
| 目标用户来源 | 表单隐藏字段（可篡改） | session 当前用户 |
| CSRF 防护 | 无 | Token 校验 |
| 密码长度 | 无限制（可设空密码） | 最少 6 位 |
| 确认密码校验 | 仅前端 | 后端校验两次一致 |
