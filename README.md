# Flask 用户管理系统

基于 Python Flask + SQLite3 开发的 Web 用户信息管理系统，包含完整的登录注册、用户搜索、头像上传、个人中心、充值、动态页面加载功能。本项目同时作为 Web 安全课程实训平台，每个功能模块均配有对应的安全审计报告与修复代码。

---

## 功能模块

| 模块 | 路由 | 功能说明 | 登录要求 |
|:---|:---|:---|:---:|
| 登录 | `/login` | 用户名密码认证 | 否 |
| 注册 | `/register` | 新用户注册 | 否 |
| 首页 | `/` | 用户信息展示与搜索入口 | 否 |
| 搜索 | `/search` | 用户名/邮箱模糊查询 | 是 |
| 头像上传 | `/upload` | 用户图片文件上传 | 是 |
| 个人中心 | `/profile` | 查看个人资料与余额 | 是 |
| 充值 | `/recharge` | 账户余额充值 | 是 |
| 动态页面 | `/page` | 加载静态页面内容（帮助中心） | 否 |
| 退出 | `/logout` | 清除会话 | 否 |

---

## 快速启动

### 环境要求

- Python 3.10+
- Flask 3.x

### 安装运行

```bash
git clone https://github.com/halalahya/user-management-platform.git
cd user-management-platform
pip install flask
python app.py
```

访问 **https://127.0.0.1:5000**（自签名证书，浏览器提示"高级→继续前往"即可）。

### 默认账号

| 用户名 | 密码 |
|:---|:---|
| admin | admin123 |
| alice | alice2025 |

---

## 项目结构

```
user-management-platform/
├── app.py                          # 主应用（含全部路由）
├── templates/                      # HTML 模板
│   ├── base.html                   # 基础布局
│   ├── index.html                  # 首页
│   ├── login.html                  # 登录页
│   ├── register.html               # 注册页
│   ├── profile.html                # 个人中心
│   └── upload.html                 # 头像上传
├── static/                         # 静态资源
│   ├── css/style.css
│   └── uploads/                    # 上传文件存储
├── pages/                          # 静态页面目录
│   └── help.html                   # 帮助中心
├── ssl/                            # SSL 证书
├── data/                           # SQLite 数据库
│
├── original-version/               # 原始有漏洞版本（首次审计）
├── fixed-version/                  # 修复后版本（首次审计）
├── sqli-lab/                       # SQL 注入专项审计
├── file-upload-audit/              # 文件上传专项审计
├── profile-audit/                  # 个人中心与充值专项审计
└── page-audit/                     # 动态页面加载专项审计
```

---

## 安全审计总览

本项目累计完成了 5 轮安全审计，共发现并修复 **31 项安全漏洞**。

### 审计批次

| 批次 | 审计模块 | 漏洞数 | 对应目录 |
|:---|:---|:---:|:---|
| 第 1 轮 | 基础安全加固（密码、会话、CSRF 等） | 15 | `fixed-version/` |
| 第 2 轮 | SQL 注入（搜索 + 注册） | 3 | `sqli-lab/` |
| 第 3 轮 | 文件上传（头像上传） | 4 | `file-upload-audit/` |
| 第 4 轮 | 个人中心与充值 | 6 | `profile-audit/` |
| 第 5 轮 | 动态页面加载（路径穿越） | 3 | `page-audit/` |

### 漏洞类型分布

| 漏洞类型 | 数量 | 涉及模块 |
|:---|:---:|:---|
| 密码安全 | 3 | 登录、注册 |
| 通信安全 | 2 | 全局配置 |
| CSRF 防护 | 2 | 登录、充值 |
| 会话安全 | 4 | 全局配置 |
| 信息泄露 | 5 | 登录页、首页、个人中心 |
| SQL 注入 | 3 | 搜索、注册 |
| 文件上传 | 4 | 头像上传 |
| 权限校验 | 3 | 个人中心、充值 |
| 输入校验 | 3 | 充值、搜索 |
| 路径穿越 | 2 | 动态页面加载 |

---

## 各模块审计详情

### 第 1 轮：基础安全加固

完整代码：`original-version/`（漏洞版）→ `fixed-version/`（修复版）

主要修复：
- 密码明文存储 → 加盐哈希
- HTTP 明文 → HTTPS 加密
- 会话 Cookie 安全配置
- CSRF Token 防护
- 安全响应头（HSTS、CSP、X-Frame-Options 等）

### 第 2 轮：SQL 注入审计

完整代码：`sqli-lab/vulnerable-app.py`（漏洞版）→ `sqli-lab/fixed-app.py`（修复版）

| 漏洞 | 修复方式 |
|:---|:---|
| UNION 注入 | 参数化查询 `?` 占位符 |
| OR 万能注入 | 参数化查询 `?` 占位符 |
| 注册注入 | 参数化查询 `?` 占位符 |

### 第 3 轮：文件上传审计

完整代码：`file-upload-audit/vulnerable/` → `file-upload-audit/fixed/`

| 漏洞 | 修复方式 |
|:---|:---|
| 任意文件上传 | 扩展名白名单 |
| 同名文件覆盖 | UUID 唯一化命名 |
| 文件内容伪造 | 魔术头校验 |
| 体积过大 | 上限 16MB → 5MB |

### 第 4 轮：个人中心与充值审计

完整代码：`profile-audit/vulnerable/` → `profile-audit/fixed/`

| 漏洞 | 修复方式 |
|:---|:---|
| 越权访问 | session 登录校验 |
| 未授权充值 | session 登录校验 |
| 负金额充值 | 正负校验 |
| 大额溢出 | 范围限制 |
| CSRF 伪造 | CSRF Token |
| 硬编码越权 | 无参链接自动解析 |

### 第 5 轮：动态页面加载审计

完整代码：`page-audit/vulnerable/` → `page-audit/fixed/`

| 漏洞 | 修复方式 |
|:---|:---|
| 路径穿越 | 正则白名单 + 路径规范化 |
| 敏感文件泄露 | 路径限制在 pages/ 目录 |
| 渲染风险 | 白名单确保安全内容 |

---

## 安全加固总结

| 安全维度 | 修复前 | 修复后 |
|:---|:---|:---|
| 密码存储 | 明文硬编码 | 加盐哈希 |
| 通信加密 | HTTP 明文 | HTTPS + HSTS |
| 会话安全 | 无配置 | HttpOnly + Secure + SameSite + 2h 过期 |
| 密钥管理 | 硬编码弱密钥 | 环境变量 / 随机 256 位 |
| CSRF 防护 | 无 | Token 校验 |
| 点击挟持 | 无 | X-Frame-Options + CSP |
| SQL 注入 | f-string 拼接 | 参数化查询 |
| 文件上传 | 无限制 | 白名单 + 魔术头校验 |
| 暴力破解 | 无限制 | 5 次锁定 15 分钟 |
| 路径穿越 | 无校验 | 白名单 + 路径校验 |
| 权限校验 | 无 | session 登录校验 |

---

## 免责声明

本项目包含有漏洞版本的源代码，仅用于 **网络安全教学与合法授权的安全测试**。禁止将漏洞代码用于未经授权的系统测试或非法攻击。任何非法使用造成的法律后果由使用者自行承担。
