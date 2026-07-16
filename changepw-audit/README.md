# 修改密码功能模块 — 安全审计与修复

## 项目介绍

本项目基于 Flask + SQLite3 开发，在原有登录、注册、搜索、头像上传、个人中心、充值、动态页面加载功能基础上，本次新增了**密码修改功能**。该功能允许已登录用户在个人中心页面修改自己的登录密码。

本模块对该功能进行完整安全审计，共发现 5 项安全漏洞，并逐一实施修复。

## 原有基础功能说明

| 路由 | 方法 | 功能 | 登录要求 |
|------|------|------|---------|
| `/` | GET | 首页 | 否 |
| `/login` | GET/POST | 登录 | 否 |
| `/register` | GET/POST | 注册 | 否 |
| `/search` | GET | 搜索用户 | 是 |
| `/upload` | GET/POST | 上传头像 | 是 |
| `/profile` | GET | 个人中心 | 是 |
| `/recharge` | POST | 充值 | 是 |
| `/page` | GET | 动态页面加载 | 否 |
| `/logout` | GET | 退出登录 | 否 |

## 新增修改密码功能需求原文

1. 新增路由 `/change-password`，支持 POST
2. 从表单接收 `username` 和 `new_password` 参数，不需要验证原密码
3. 不需要 CSRF Token 验证
4. 不需要验证当前 session 用户和提交的 username 是否一致
5. 在 profile.html 添加修改密码表单

## 漏洞完整汇总清单

| 编号 | 漏洞名称 | 风险等级 | CVSS | 状态 |
|------|---------|---------|:----:|:----:|
| VULN-CP-01 | 无原密码校验（可直接修改任意用户密码） | 高危 | 8.2 | 已修复 |
| VULN-CP-02 | 隐藏字段可篡改（越权修改他人密码） | 高危 | 7.5 | 已修复 |
| VULN-CP-03 | 无 CSRF Token 校验（跨站请求伪造） | 中危 | 6.5 | 已修复 |
| VULN-CP-04 | 无密码强度校验（弱密码可被设置） | 中危 | 5.3 | 已修复 |
| VULN-CP-05 | 确认密码仅前端校验（后端未验证一致性） | 低危 | 3.3 | 已修复 |

---

## 各漏洞详细修复方案

### VULN-CP-01：无原密码校验

**漏洞原理：** 修改密码接口未要求用户输入原密码进行身份验证。攻击者只要获得了已登录用户的会话，即可直接修改该账号的密码。

**原始代码：**
```python
username = request.form.get("username")
new_password = request.form.get("new_password")
if username in USERS:
    USERS[username]["password"] = generate_password_hash(new_password)
```

**修复代码：**
```python
username = session.get("username")
old_password = request.form.get("old_password")
new_password = request.form.get("new_password")
if not check_password_hash(USERS[username]["password"], old_password):
    return "原密码错误", 403
```

**修复效果：** 不传原密码时返回"缺少参数"；原密码错误时返回"原密码错误"；原密码验证通过后才执行修改。

---

### VULN-CP-02：隐藏字段可篡改

**漏洞原理：** 表单中的 username 通过隐藏字段传递，攻击者通过浏览器开发者工具或 curl 可修改该字段值，将密码修改指向其他用户。

**原始代码：**
```html
<input type="hidden" name="username" value="admin">
```
```python
username = request.form.get("username")
```

**修复代码：**
```python
# 后端从 session 获取当前登录用户，前端表单不再传递 username
username = session.get("username")
```

**修复效果：** 攻击者篡改表单中的 username 字段不再生效，系统始终使用当前 session 中的用户身份。

---

### VULN-CP-03：无 CSRF Token 校验

**漏洞原理：** 修改密码接口未校验 CSRF Token，攻击者可构造恶意 HTML 页面诱导已登录用户访问，实现跨站密码篡改。

**修复代码：**
```python
if not validate_csrf_token():
    return render_template("login.html", error="会话已过期，请刷新页面后重试！")
```
```html
<input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
```

**修复效果：** 缺少 CSRF Token 的 POST 请求被拒绝。

---

### VULN-CP-04：无密码强度校验

**漏洞原理：** 后端未对 new_password 做长度校验，空密码或单字符密码可被接受，极易被暴力破解。

**修复代码：**
```python
if len(new_password) < 6:
    return "密码长度不能少于6位", 400
if len(new_password) > 128:
    return "密码长度不能超过128位", 400
```

**修复效果：** 少于 6 位的密码被拒绝，防止用户设置弱密码。

---

### VULN-CP-05：确认密码仅前端校验

**漏洞原理：** 后端未校验 confirm_password，直接发送 curl 请求可绕过前端限制设置不一致的密码。

**修复代码：**
```python
confirm_password = request.form.get("confirm_password")
if new_password != confirm_password:
    return "两次输入的密码不一致", 400
```

**修复效果：** 两次密码不一致时后端拒绝修改，无法绕过。

---

## 修复前后代码对比

| 对比项 | 漏洞版 | 修复版 |
|-------|-------|-------|
| 原密码校验 | 无，直接修改 | 需验证原密码正确性 |
| 目标用户来源 | 表单隐藏字段 | session 当前登录用户 |
| CSRF Token | 无 | 表单添加 + 后端校验 |
| 密码最小长度 | 无限制 | 6 位 |
| 确认密码校验 | 仅前端 HTML5 required | 后端也校验一致性 |
| 越权修改他人密码 | 可绕过（篡改字段） | 不允许（锁定当前用户） |

## POC 复现操作

```bash
# 登录
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt

# 漏洞版：无需原密码即可修改
curl -d "username=admin&new_password=hacked" -b /tmp/cookies.txt http://127.0.0.1:5000/change-password

# 修复版验证：
# 1. 无原密码 → 返回"缺少参数"
# 2. 原密码错误 → 返回"原密码错误"
# 3. 弱密码 → 返回"密码长度不能少于6位"
# 4. 确认密码不一致 → 返回"两次输入的密码不一致"
# 5. 正常修改 → 原密码正确、新密码合规、两次一致 → 成功
```

## 部署启动命令

```bash
pip install flask
cd 项目目录
python app.py
# 访问 https://127.0.0.1:5000
# 默认账号 admin / admin123
```

## 目录结构

```
changepw-audit/
├── 1-SECURITY_AUDIT.md            # 安全审计报告
├── vulnerable/                    # 漏洞版代码
│   ├── app.py                    # 含漏洞的完整后端
│   └── profile.html              # 含漏洞的个人中心模板
├── fixed/                        # 修复版代码
│   ├── app.py                    # 修复后的完整后端
│   └── profile.html              # 修复后的个人中心模板
└── README.md                     # 本文件
```

## 免责声明

本仓库提供的漏洞代码和 POC 测试命令仅用于 **网络安全教学与合法授权测试**。禁止用于未经授权的系统测试或攻击，任何非法使用造成的法律后果由使用者自行承担。请遵守《中华人民共和国网络安全法》及相关法律法规。
