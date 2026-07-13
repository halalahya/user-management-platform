# 动态页面加载模块 — 安全审计与修复

## 项目介绍

本项目基于 Flask + SQLite3 开发，在原有用户登录、注册、搜索、头像上传、个人中心、充值功能基础上，新增了动态页面加载功能。该功能通过 `/page` 路由读取 `pages/` 目录下的 HTML 文件并在首页展示，用于实现帮助中心等静态页面内容。

## 运行环境

| 项目 | 版本 |
|------|------|
| Python | 3.10+ |
| Flask | 3.x |
| 数据库 | SQLite3 |

## 目录结构

```
page-audit/
├── 1-SECURITY_AUDIT.md              # 安全审计报告
├── vulnerable/                      # 漏洞原版代码
│   ├── app.py                      # 完整后端（含所有路由）
│   ├── index.html                  # 首页模板
│   └── help.html                   # 帮助页面
├── fixed/                          # 修复版代码
│   ├── app.py                      # 修复后的完整后端
│   ├── index.html                  # 首页模板
│   └── help.html                   # 帮助页面
└── README.md                       # 本文件
```

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
| `/logout` | GET | 退出登录 | 否 |

## 新增动态页面加载功能介绍

| 路由 | 方法 | 功能 | 参数 |
|------|------|------|------|
| `/page` | GET | 读取 pages/ 目录下的文件并展示在首页 | `name`（页面名称） |

**正常使用：** 访问 `/page?name=help` 可在首页展示 `pages/help.html` 文件内容。未登录用户也可查看。

---

## 漏洞风险说明

本次审计针对 `/page` 路由发现 **3 项安全漏洞**，请见完整审计报告 `1-SECURITY_AUDIT.md`。

### VULN-PG-01：路径穿越读取任意文件（高危）

**漏洞代码：**
```python
filepath = os.path.join("pages", name)   # name 未做任何过滤
if os.path.isfile(filepath):
    with open(filepath, "r") as f:
        page_content = f.read()
```

**危害：** 攻击者传入 `../../etc/passwd` 即可读取系统任意文件。

**修复方式：** 正则白名单 `^[a-zA-Z0-9_-]+$` + `os.path.realpath()` 路径前缀校验。

**修复代码：**
```python
if not re.match(r'^[a-zA-Z0-9_-]+$', name):
    return "非法的页面名称", 400

pages_dir = os.path.join(app.root_path, "pages")
safe_path = os.path.realpath(os.path.join(pages_dir, name))
if not safe_path.startswith(os.path.realpath(pages_dir)):
    return "非法的页面名称", 400
```

### VULN-PG-02：敏感文件信息泄露（高危）

**漏洞代码：** 同 VULN-PG-01，读取的文件内容直接返回给客户端。

**修复方式：** 路径限制在 `pages/` 目录内，无法读取目录外文件。

### VULN-PG-03：页面内容未限制渲染范围（低危）

**漏洞代码：** `{{ page_content | safe }}`

**修复方式：** 白名单限制页面名称后，pages 目录内均为安全的静态 HTML 页面，风险可控。

---

## 漏洞修复方案

### 修复前后代码对比

**路由入口校验（新增）：**
```python
# 漏洞版：无校验
name = request.args.get("name", "")
filepath = os.path.join("pages", name)

# 修复版：正则白名单 + 路径规范化
if not re.match(r'^[a-zA-Z0-9_-]+$', name):
    return "非法的页面名称", 400
pages_dir = os.path.join(app.root_path, "pages")
safe_path = os.path.realpath(os.path.join(pages_dir, name))
if not safe_path.startswith(os.path.realpath(pages_dir)):
    return "非法的页面名称", 400
```

**文件读取逻辑（优化）：**
```python
# 漏洞版：直接拼接用户输入
filepath = os.path.join("pages", name)
if os.path.isfile(filepath): ...

# 修复版：在安全路径基础上读取
if os.path.isfile(safe_path): ...
else:
    html_path = safe_path + ".html"
    if os.path.isfile(html_path): ...
```

### 修复前后对比

| 对比项 | 漏洞版 | 修复版 |
|--------|-------|-------|
| 路径校验 | 无，直接拼接用户输入 | 正则白名单 `^[a-zA-Z0-9_-]+$` + 路径规范化 |
| 文件读取范围 | 服务器任意位置 | 仅限 pages/ 目录 |
| `../../etc/passwd` 攻击 | 读取成功，返回文件内容 | 返回"非法的页面名称" |
| `../app.py` 攻击 | 读取成功，返回源码 | 返回"非法的页面名称" |
| 正常功能 `/page?name=help` | 正常显示帮助中心 | 正常显示帮助中心 |

### POC 复现操作步骤

```bash
# 1. 路径穿越读取系统文件（漏洞版）
curl "http://127.0.0.1:5000/page?name=../../etc/passwd"

# 2. 路径穿越读取应用源码（漏洞版）
curl "http://127.0.0.1:5000/page?name=../app.py"

# 3. 正常功能测试
curl "http://127.0.0.1:5000/page?name=help"

# 4. 修复版验证
# 漏洞版：返回文件内容
# 修复版：返回"非法的页面名称"
```

### 启动与测试

```bash
# 安装依赖
pip install flask

# 启动应用
cd <项目目录>
python app.py

# 访问 https://127.0.0.1:5000

# 正常功能测试
curl "https://127.0.0.1:5000/page?name=help"

# 漏洞复现测试（漏洞版）
curl "https://127.0.0.1:5000/page?name=../../etc/passwd"
# 漏洞版：返回文件内容；修复版：返回"非法的页面名称"
```

## 安全加固总结

| 漏洞 | 修复方式 | 效果 |
|------|---------|------|
| 路径穿越 | 正则白名单 `^[a-zA-Z0-9_-]+$` | `../`、`/` 等字符被直接拒绝 |
| 文件泄露 | `os.path.realpath()` 路径前缀校验 | 读取范围被限制在 `pages/` 目录内 |
| 渲染风险 | 白名单确保仅读取预置页面 | pages/ 目录内容可控 |

---

## 免责声明

本仓库提供的漏洞代码和 POC 测试命令仅用于 **网络安全教学与合法授权测试**。禁止用于未经授权的系统测试或攻击，任何非法使用造成的法律后果由使用者自行承担。请遵守《中华人民共和国网络安全法》及相关法律法规。
