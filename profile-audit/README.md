# 个人中心与充值模块 — 安全审计与修复

## 项目介绍

本项目是一个基于 Flask + SQLite3 的用户管理系统，在原有登录、注册、搜索、头像上传功能基础上，本次新增了**个人中心**和**充值**两大功能模块。

| 新增路由 | 功能 | 参数 |
|---------|------|------|
| `GET /profile` | 个人中心，展示用户 ID/用户名/邮箱/手机/余额 | `user_id`（URL 参数，可选） |
| `POST /recharge` | 充值，增加用户余额 | `user_id` + `amount`（表单参数） |

## 运行环境

| 项目 | 版本 |
|------|------|
| Python | 3.10+ |
| Flask | 3.x |
| 数据库 | SQLite3 |

## 目录结构

```
profile-audit/
├── 1-AUDIT_REPORT.md              # 完整安全审计报告
├── vulnerable/                    # 漏洞原版代码
│   ├── app.py                    # 完整后端（含所有路由）
│   ├── profile.html              # 个人中心页面
│   ├── base.html                 # 基础模板
│   └── index.html                # 首页
├── fixed/                        # 修复版代码
│   ├── app_routes_fixed.py       # 修复后的路由代码片段
│   ├── profile.html              # 修复后个人中心页面
│   ├── base.html                 # 修复后基础模板
│   └── index.html                # 修复后首页
└── README.md                     # 本文件
```

---

## 原生漏洞版说明

漏洞版代码存放于 `vulnerable/` 目录，严格遵循原始开发需求编写，故意保留了以下不安全设计：

- `/profile` 无登录校验，任何人可查看任意用户资料
- `/recharge` 无登录校验 + 无金额校验 + 无 CSRF Token
- `base.html` 和 `index.html` 硬编码 `user_id=1`

---

## 漏洞清单与修复方案

### VULN-PR-01：越权访问用户资料（高危）

| 项目 | 内容 |
|------|------|
| **漏洞成因** | `/profile` 路由未校验用户是否登录，未授权者可访问任意用户资料 |
| **原始代码** | `def profile(): user_id = request.args.get("user_id")` → 直接查询数据库 |
| **修复代码** | `if "username" not in session: return redirect("/login")` |
| **修复效果** | 未登录用户访问 `/profile` 自动跳转到登录页 |

### VULN-PR-02：未授权充值（高危）

| 项目 | 内容 |
|------|------|
| **漏洞成因** | `/recharge` 路由未校验用户是否登录，任何人都可修改余额 |
| **原始代码** | `def recharge(): user_id = request.form.get("user_id")` → 直接更新数据库 |
| **修复代码** | `if "username" not in session: return redirect("/login")` |
| **修复效果** | 未登录用户无法调用充值接口 |

### VULN-PR-03：负金额充值（高危）

| 项目 | 内容 |
|------|------|
| **漏洞成因** | `amount` 参数无正负校验，传入负值可扣减余额 |
| **原始代码** | `new_balance = current_balance + int(amount)` |
| **修复代码** | `if amount_val <= 0: return "金额必须为正整数", 400` |
| **修复效果** | 负数或零金额被拦截 |

### VULN-PR-04：大额整数溢出（中危）

| 项目 | 内容 |
|------|------|
| **漏洞成因** | `amount` 直接转 `int()` 无大小限制，可传入超大数值 |
| **原始代码** | `new_balance = current_balance + int(amount)` |
| **修复代码** | `if amount_val > 1000000: return "单次充值金额不能超过 1000000", 400` |
| **修复效果** | 超过 1000000 的金额被拦截 |

### VULN-PR-05：CSRF 跨站伪造充值（中危）

| 项目 | 内容 |
|------|------|
| **漏洞成因** | 充值表单未包含 CSRF Token，可被跨站利用 |
| **原始代码** | `<input type="hidden" name="user_id" value="{{ user.id }}">` |
| **修复代码** | `<input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">` + 后端 `validate_csrf_token()` 校验 |
| **修复效果** | 缺少 CSRF Token 的请求被拒绝 |

### VULN-PR-06：硬编码 user_id 致越权（低危）

| 项目 | 内容 |
|------|------|
| **漏洞成因** | 导航栏和首页的"个人中心"链接硬编码 `user_id=1` |
| **原始代码** | `<a href="/profile?user_id=1">个人中心</a>` |
| **修复代码** | `<a href="/profile">个人中心</a>`，由路由自动解析当前用户 |
| **修复效果** | 无参跳转时自动展示当前登录用户资料 |

### 修复前后对比

| 对比项 | 漏洞版 | 修复版 |
|--------|-------|-------|
| 个人中心访问 | 无登录校验，任意访问 | 需登录，未登录跳转 |
| 充值权限 | 无登录校验，匿名可充 | 需登录 + CSRF Token |
| 金额正负限制 | 无校验，负值可扣款 | 正负校验，负值拒绝 |
| 金额大小限制 | 无上限，超大数值可写入 | 上限 1000000 |
| CSRF 防护 | 无 | Token 验证 |
| 导航栏链接 | 硬编码 user_id=1 | 无参自动解析当前用户 |

---

## 部署运行教程

### 环境依赖

```bash
pip install flask werkzeug
```

### 启动命令

```bash
# 启动漏洞版（端口 5000）
cd vulnerable
python app.py
# 访问 https://127.0.0.1:5000
```

### 功能访问路径

| 路径 | 说明 |
|------|------|
| `https://127.0.0.1:5000/login` | 登录（admin / admin123） |
| `https://127.0.0.1:5000/profile` | 个人中心（无参跳转，查看自己） |
| `https://127.0.0.1:5000/profile?user_id=2` | 查看其他用户资料 |
| `https://127.0.0.1:5000/recharge` | 充值（POST 提交 user_id + amount） |

### 漏洞复现操作步骤

```bash
# 1. 未登录查看用户资料（VULN-PR-01）
curl http://127.0.0.1:5000/profile?user_id=1

# 2. 未登录充值（VULN-PR-02）
curl -d "user_id=1&amount=99999" http://127.0.0.1:5000/recharge

# 3. 负金额扣款（VULN-PR-03）
curl -d "user_id=2&amount=-99999" http://127.0.0.1:5000/recharge

# 4. 超大金额溢出（VULN-PR-04）
curl -d "user_id=1&amount=99999999999999999999" http://127.0.0.1:5000/recharge
```

### 修复后验证步骤

```bash
# 1. 验证未登录被拦截
curl http://127.0.0.1:5000/profile?user_id=1
# 期望结果：302 跳转到登录页

# 2. 验证负金额被拦截（先登录）
curl -X POST -d "user_id=1&amount=-500" http://127.0.0.1:5000/recharge
# 期望结果：返回"金额必须为正整数"

# 3. 验证超大金额被拦截
curl -X POST -d "user_id=1&amount=99999999999" http://127.0.0.1:5000/recharge
# 期望结果：返回"单次充值金额不能超过 1000000"

# 4. 验证正常充值可用（先获取 CSRF Token）
# 正常浏览器操作，充值表单已包含 CSRF Token
```

---

## 免责声明

本仓库提供的漏洞代码和 POC 测试命令仅用于 **网络安全教学与合法授权测试**。禁止用于未经授权的系统测试或攻击，任何非法使用造成的法律后果由使用者自行承担。请遵守《中华人民共和国网络安全法》及相关法律法规。
