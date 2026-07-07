# 用户信息管理平台 — 安全审计与修复报告

> **项目概述**：基于 Flask 的简易用户信息管理平台，包含登录、用户信息展示、退出功能。  
> **审计目标**：对原始代码进行全量安全审计，查找并修复所有安全漏洞。  
> **漏洞总数**：共发现并修复 **15 个安全漏洞**。

---

## 项目结构

```
user-management-platform/
├── original-version/          ← 原始有漏洞版本（审计前）
│   ├── app.py
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html
│   │   └── login.html
│   └── static/
│       └── css/
│           └── style.css
├── fixed-version/             ← 修复后版本（审计后）
│   ├── app.py
│   ├── requirements.txt
│   ├── ssl/
│   │   ├── cert.pem
│   │   └── key.pem
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html
│   │   └── login.html
│   └── static/
│       └── css/
│           └── style.css
└── README.md                  ← 本报告文件
```

---

## 运行方式

### 原始有漏洞版本

```bash
cd original-version
pip install flask
python app.py
# 访问 http://127.0.0.1:5000
```

### 修复后版本

```bash
cd fixed-version
pip install -r requirements.txt

# 设置用户密码（如不设置则启动时自动生成随机密码）
export ADMIN_PASSWORD='your-admin-password'
export ALICE_PASSWORD='your-alice-password'

python app.py
# 访问 https://127.0.0.1:5000
```

> 修复版第一次运行会自动生成自签名 SSL 证书。浏览器会提示不安全，点击"高级 → 继续前往"即可。

---

## 原始漏洞总览

| # | 漏洞名称 | CWE 编号 | 危险等级 |
|---|---------|----------|---------|
| 1 | ⛔ 密码明文存储与硬编码凭据 | CWE-256 / CWE-798 | **严重** |
| 2 | ⛔ 通信层未加密（明文传输 + 无 HTTPS） | CWE-319 / CWE-326 | **严重** |
| 3 | ⚠️ Session 密钥硬编码且过于简单 | CWE-330 | **高危** |
| 4 | ⚠️ 登录后密码明文回显至前端 | CWE-200 | **高危** |
| 5 | ⚠️ 调试注释泄露默认管理员凭据 | CWE-200 / CWE-489 | **高危** |
| 6 | ⚠️ 缺少 CSRF 保护 | CWE-352 | **高危** |
| 7 | ⚠️ Session Cookie 安全配置缺失（Secure / HttpOnly / SameSite / 过期时间） | CWE-614 / CWE-1004 / CWE-1275 / CWE-613 | **高危** |
| 8 | ⚠️ 缺少点击挟持防护 | CWE-1021 | **中危** |
| 9 | ⚠️ 缺少 HSTS 头 | CWE-326 | **中危** |
| 10 | ⚠️ Content-Security-Policy 头不完整 | CWE-693 | **中危** |
| 11 | 🔵 缺少 X-Content-Type-Options 头 | CWE-693 | **低危** |
| 12 | ⚠️ 开发环境安全配置遗留（Debug 模式 + 监听 0.0.0.0） | CWE-489 / CWE-942 | **中危** |
| 13 | 🔵 缺少表单输入校验 | CWE-20 | **低危** |
| 14 | 🔵 邮箱地址前端泄露 | CWE-200 | **低危** |
| 15 | ⚠️ 认证机制缺陷（暴力破解 + 弱密码） | CWE-307 / CWE-521 | **中危** |

---

## 逐漏洞修复详情

---

### 漏洞 #1：密码明文存储与硬编码凭据

| 维度 | 内容 |
|------|------|
| **问题** | 用户密码以明文形式硬编码在 `USERS` 字典中，且密码字面量出现在源码中，代码泄露后密码直接暴露 |
| **原始代码** | `"password": "admin123"` |
| **修复代码** | 从环境变量 `ADMIN_PASSWORD` / `ALICE_PASSWORD` 读取密码；使用 `generate_password_hash()` 加盐哈希存储 |
| **修复说明** | 源码中不出现任何形式的密码字面量；每次哈希使用随机盐值；登录时通过 `check_password_hash()` 验证 |

**修复代码片段：**
```python
_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not _ADMIN_PASSWORD:
    _ADMIN_PASSWORD = secrets.token_hex(16)

USERS = {
    "admin": {
        "password": generate_password_hash(_ADMIN_PASSWORD),
    },
}

if check_password_hash(USERS[username]["password"], password):
```

---

### 漏洞 #2：通信层未加密

| 维度 | 内容 |
|------|------|
| **问题** | 应用运行在 HTTP 明文协议上，所有传输数据（密码、session cookie、个人信息）均可被网络嗅探截获 |
| **原始代码** | `app.run(host="0.0.0.0", port=5000)`（无 `ssl_context`） |
| **修复代码** | 加载 SSL 证书，使用 `ssl_context=(SSL_CERT, SSL_KEY)` 强制 HTTPS |
| **修复说明** | 所有通信经 TLS 加密，密码和 cookie 在传输过程中不可被中间人读取 |

**修复代码片段：**
```python
app.run(
    debug=False,
    host="127.0.0.1",
    port=5000,
    ssl_context=(SSL_CERT, SSL_KEY)
)
```

---

### 漏洞 #3：Session 密钥硬编码且过于简单

| 维度 | 内容 |
|------|------|
| **问题** | `secret_key` 硬编码为 `"dev-key-2025"`，可被猜测并伪造 session cookie |
| **原始代码** | `app.secret_key = "dev-key-2025"` |
| **修复代码** | 从环境变量 `FLASK_SECRET_KEY` 读取，不存在则使用 `secrets.token_hex(32)` 生成随机密钥 |
| **修复说明** | 密钥不可预测，防止 session 伪造攻击 |

**修复代码片段：**
```python
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
```

---

### 漏洞 #4：登录后密码明文回显至前端

| 维度 | 内容 |
|------|------|
| **问题** | 登录后将包含 `password` 字段的完整用户信息传递给模板并渲染到页面上 |
| **原始代码** | `user_info = USERS[username]` + `{{ user.password }}` |
| **修复代码** | 新增 `sanitize_user_info()` 函数过滤密码字段；模板中删除密码渲染行 |
| **修复说明** | 个人信息页面不再显示密码，防止截屏或页面审查泄露凭据 |

**修复代码片段：**
```python
def sanitize_user_info(user_info):
    return {
        "username": user_info["username"],
        "phone": user_info["phone"],
        "role": user_info["role"],
        "balance": user_info["balance"]
    }
```

---

### 漏洞 #5：调试注释泄露默认管理员凭据

| 维度 | 内容 |
|------|------|
| **问题** | HTML 源码注释中直接写明管理员用户名和密码，查看网页源代码即可获取 |
| **原始代码** | `<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->` |
| **修复代码** | 删除该调试注释 |
| **修复说明** | 攻击者无法通过查看页面源码获取管理员凭据 |

---

### 漏洞 #6：缺少 CSRF 保护

| 维度 | 内容 |
|------|------|
| **问题** | 登录表单无 CSRF Token，攻击者可构造恶意页面诱导用户提交跨站请求 |
| **原始代码** | `<form method="POST" action="/login">`（无 CSRF 隐藏字段） |
| **修复代码** | `secrets` 模块生成一次性 Token，Jinja2 全局注入，表单添加隐藏字段，POST 时验证 |
| **修复说明** | 每个表单包含唯一 Token，服务端验证通过后才处理请求，防止 CSRF 攻击 |

**修复代码片段：**
```python
def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

app.jinja_env.globals["csrf_token"] = generate_csrf_token
```

```html
<input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
```

---

### 漏洞 #7：Session Cookie 安全配置缺失

| 维度 | 内容 |
|------|------|
| **问题** | Session cookie 未设置 Secure、HttpOnly、SameSite 标志，且无过期时间，存在会话劫持风险 |
| **原始代码** | 无 Session Cookie 相关配置 |
| **修复代码** | 配置 `SESSION_COOKIE_HTTPONLY`、`SESSION_COOKIE_SAMESITE`、`SESSION_COOKIE_SECURE`、`PERMANENT_SESSION_LIFETIME` |
| **修复说明** | 禁止 JavaScript 读取 cookie、仅 HTTPS 传输、限制跨站发送、2 小时会话超时 |

**修复代码片段：**
```python
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
```

---

### 漏洞 #8：缺少点击挟持防护

| 维度 | 内容 |
|------|------|
| **问题** | 未设置 `X-Frame-Options` 响应头，页面可被嵌入第三方 iframe 实施点击挟持 |
| **原始代码** | 无相关响应头 |
| **修复代码** | `response.headers["X-Frame-Options"] = "DENY"` |
| **修复说明** | 禁止页面被 iframe 嵌套加载，同时在 CSP 中设置 `frame-ancestors 'none'` 双重防护 |

---

### 漏洞 #9：缺少 HSTS 头

| 维度 | 内容 |
|------|------|
| **问题** | 未设置 `Strict-Transport-Security`，浏览器可能回退到 HTTP 连接 |
| **原始代码** | 无相关响应头 |
| **修复代码** | `response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"` |
| **修复说明** | 强制浏览器在 1 年内仅通过 HTTPS 访问，防止协议降级攻击 |

---

### 漏洞 #10：Content-Security-Policy 头不完整

| 维度 | 内容 |
|------|------|
| **问题** | 仅设置了 `frame-ancestors`，缺少 `script-src`、`style-src` 等核心指令，无法有效防御 XSS |
| **原始代码** | 无 CSP 头 |
| **修复代码** | 设置包含 `default-src`、`script-src`、`style-src`、`frame-ancestors` 的完整 CSP 策略 |
| **修复说明** | 限制仅加载同源脚本和样式资源，降低 XSS 和数据注入风险 |

**修复代码片段：**
```python
response.headers["Content-Security-Policy"] = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "frame-ancestors 'none'"
)
```

---

### 漏洞 #11：缺少 X-Content-Type-Options 头

| 维度 | 内容 |
|------|------|
| **问题** | 未设置 `X-Content-Type-Options`，浏览器可能执行 MIME 嗅探 |
| **原始代码** | 无相关响应头 |
| **修复代码** | `response.headers["X-Content-Type-Options"] = "nosniff"` |
| **修复说明** | 禁止 MIME 嗅探，浏览器严格按照 Content-Type 处理响应内容 |

---

### 漏洞 #12：开发环境安全配置遗留

| 维度 | 内容 |
|------|------|
| **问题** | `debug=True` 在出错时展示调用栈和应用路径；`host="0.0.0.0"` 暴露服务到所有网络接口 |
| **原始代码** | `app.run(debug=True, host="0.0.0.0", port=5000)` |
| **修复代码** | `app.run(debug=False, host="127.0.0.1")` |
| **修复说明** | 关闭 debug 模式防止敏感信息泄露；仅监听本地回环地址 |

---

### 漏洞 #13：缺少表单输入校验

| 维度 | 内容 |
|------|------|
| **问题** | 用户名和密码输入无长度校验，可提交超长字符串 |
| **原始代码** | `<input type="text" name="username">`（无 `maxlength`） |
| **修复代码** | 前端设置 `maxlength`，后端校验空值和长度 |
| **修复说明** | 前后端双重校验，防止超长输入和空提交 |

**修复代码片段：**
```python
username = request.form.get("username", "").strip()
if not username or not password:
    return render_template("login.html", error="用户名和密码不能为空！")
if len(username) > 50 or len(password) > 128:
    return render_template("login.html", error="输入内容过长！")
```

---

### 漏洞 #14：邮箱地址前端泄露

| 维度 | 内容 |
|------|------|
| **问题** | 用户邮箱在前端页面展示，可被用于社工攻击 |
| **原始代码** | `{{ user.email }}` |
| **修复代码** | 在 `sanitize_user_info()` 中过滤 `email` 字段 |
| **修复说明** | 用户邮箱仅保存在服务端，不再向前端暴露 |

---

### 漏洞 #15：认证机制缺陷（暴力破解 + 弱密码）

| 维度 | 内容 |
|------|------|
| **问题** | 登录接口无失败次数限制，攻击者可无限暴力尝试；默认密码强度弱 |
| **原始代码** | 登录成功/失败直接返回，无计数机制；`"password": "admin123"` |
| **修复代码** | 基于 IP 的登录失败计数，5 次失败后锁定 15 分钟；密码从环境变量读取 |
| **修复说明** | 连续登录失败会被限制，暴力破解成本大幅增加；密码强度由用户自行控制 |

**修复代码片段：**
```python
if client_ip in LOGIN_ATTEMPTS:
    attempts, lockout_time = LOGIN_ATTEMPTS[client_ip]
    if attempts >= MAX_LOGIN_ATTEMPTS and not expired:
        return "登录尝试过于频繁，请稍后再试！"

# 失败记录
LOGIN_ATTEMPTS[client_ip] = [count + 1, lockout_time]
```

---

## 安全加固总结

### 加固策略覆盖

| 安全维度 | 修复前 | 修复后 |
|---------|--------|--------|
| **传输加密** | ❌ HTTP 明文 | ✅ HTTPS + HSTS |
| **密码存储** | ❌ 明文硬编码 | ✅ 环境变量读取 + 加盐哈希 |
| **会话安全** | ❌ 无配置 | ✅ HttpOnly + Secure + SameSite + 过期时间 |
| **密钥管理** | ❌ 硬编码弱密钥 | ✅ 环境变量 / 随机 64 位密钥 |
| **CSRF 防护** | ❌ 无 | ✅ 一次性 Token 验证 |
| **点击挟持** | ❌ 无 | ✅ X-Frame-Options + CSP |
| **暴力破解** | ❌ 无 | ✅ IP 级频率限制 + 锁定 |
| **信息泄露** | ❌ 密码/邮箱回显 + 调试注释 | ✅ 过滤敏感字段 + 关闭 debug |
| **输入校验** | ❌ 无 | ✅ 前后端双重校验 |
| **安全头** | ❌ 无 | ✅ CSP + HSTS + nosniff |
| **调试模式** | ❌ 开启 | ✅ 关闭 |
| **网络暴露** | ❌ 所有接口 | ✅ 仅本地回环 |

### 业务逻辑保持

以下核心业务逻辑在修复过程中保持不变：
- 用户通过用户名密码登录
- 登录后展示用户个人信息
- 登出后清除会话并跳转首页
- 错误密码提示错误信息
- 首页根据登录状态展示不同内容

### 安全建议

1. 使用正规 CA 签发的 SSL 证书（如 Let's Encrypt）替代自签名证书
2. 将用户数据迁移至数据库（SQLite/MySQL），不再硬编码在源码中
3. 实现基于角色的访问控制（RBAC），区分管理员和普通用户权限
4. 记录登录日志以便安全事件溯源
5. 为管理员账户增加二次验证

---

*报告生成时间：2026-07-07 | 审计工具：Claude Code 手动审计*
