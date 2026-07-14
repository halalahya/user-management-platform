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
2. 从表单接收 `username` 和 `new_password` 参数
3. 直接更新用户数据中的密码字段，不需要验证原密码
4. 不需要 CSRF Token 验证
5. 不需要验证当前 session 用户和提交的 username 是否一致
6. 在 profile.html 添加修改密码表单

## 漏洞完整汇总清单

| 编号 | 漏洞名称 | 风险等级 | 状态 |
|------|---------|---------|------|
| VULN-CP-01 | 无原密码校验 | 高危 | 已修复 |
| VULN-CP-02 | 隐藏字段可篡改（越权修改他人密码） | 高危 | 已修复 |
| VULN-CP-03 | 无 CSRF Token 校验 | 中危 | 已修复 |
| VULN-CP-04 | 无密码强度校验 | 中危 | 已修复 |
| VULN-CP-05 | 确认密码仅前端校验 | 低危 | 已修复 |

---

## 各漏洞详细修复方案

### VULN-CP-01：无原密码校验

**漏洞原理：** 修改密码接口未要求用户输入原密码进行身份验证。攻击者只要获得了已登录用户的会话即可修改密码。

**原始代码：**
```python
username = request.form.get("username")
new_password = request.form.get("new_password")
if username in USERS:
    USERS[username]["password"] = generate_password_hash(new_password)
```

**修复代码：**
```python
username = session.get("username")  # 从session获取
old_password = request.form.get("old_password")
new_password = request.form.get("new_password")
if not check_password_hash(USERS[username]["password"], old_password):
    return "原密码错误", 403
```

---

### VULN-CP-02：隐藏字段可篡改

**漏洞原理：** 表单中的 username 通过隐藏字段传递，攻击者可通过 curl 修改该字段值，将其他用户的密码篡改。

**原始代码：**
```html
<input type="hidden" name="username" value="admin">
```

**修复代码：**
```python
# 后端从 session 获取用户名，前端表单不再传递 username
username = session.get("username")
```

---

### VULN-CP-03：无 CSRF Token 校验

**漏洞原理：** 修改密码接口未校验 CSRF Token，可被跨站请求伪造攻击。

**修复代码：**
```python
if not validate_csrf_token():
    return render_template("login.html", error="会话已过期，请刷新页面后重试！")
```

```html
<input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
```

---

### VULN-CP-04：无密码强度校验

**漏洞原理：** 后端未对密码长度做校验，空密码或单字符密码也可能被接受。

**修复代码：**
```python
if len(new_password) < 6:
    return "密码长度不能少于6位", 400
if len(new_password) > 128:
    return "密码长度不能超过128位", 400
```

---

### VULN-CP-05：确认密码仅前端校验

**漏洞原理：** 后端未校验 confirm_password，直接发送 curl 请求可绕过前端限制。

**修复代码：**
```python
confirm_password = request.form.get("confirm_password")
if new_password != confirm_password:
    return "两次输入的密码不一致", 400
```

---

## 修复前后代码对比

| 对比项 | 漏洞版 | 修复版 |
|-------|-------|-------|
| 原密码校验 | 无，直接修改 | 需验证原密码正确性 |
| 目标用户来源 | 表单隐藏字段 | session 当前登录用户 |
| CSRF Token | 无 | 表单添加 + 后端校验 |
| 密码最小长度 | 无限制 | 6 位 |
| 确认密码校验 | 仅前端 HTML5 required | 后端 also 校验一致性 |
| 越权修改他人密码 | 可绕过 | 不允许（锁定当前用户） |

## 项目部署启动命令

```bash
# 安装依赖
pip install flask

# 启动服务
cd 项目目录
python app.py

# 访问地址
https://127.0.0.1:5000
```

## 端口访问说明

| 端口 | 协议 | 说明 |
|------|------|------|
| 5000 | HTTPS | 主应用端口（自签名证书） |

默认账号：admin / admin123

## 目录结构

```
changepw-audit/
├── 1-SECURITY_AUDIT.md              # 安全审计报告
├── vulnerable/                       # 漏洞原版代码
│   ├── app.py                       # 含漏洞的完整后端
│   └── profile.html                 # 含漏洞的个人中心模板
├── fixed/                           # 修复版代码
│   ├── app.py                       # 修复后的完整后端
│   └── profile.html                 # 修复后的个人中心模板
└── README.md                        # 本文件
```
