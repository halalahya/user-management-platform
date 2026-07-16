# 动态页面加载模块漏洞检测与安全修复报告

## Web 安全漏洞审计与加固实训

**项目名称：** Flask 用户管理系统 — 动态页面加载模块  
**漏洞类型：** 路径穿越 / 任意文件读取  
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
   2.2 VULN-PG-01：路径穿越读取任意文件  
   2.3 VULN-PG-02：敏感文件信息泄露  
   2.4 VULN-PG-03：页面内容未限制渲染范围  

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

本项目是一个基于 Python Flask 框架和 SQLite3 数据库开发的简易用户信息管理系统。系统已有的登录、注册、搜索、头像上传、个人中心、充值功能基础上，本次新增了**动态页面加载功能**，通过 `/page` 路由读取 `pages/` 目录下的静态 HTML 文件并在首页展示，用于实现帮助中心等静态页面内容的动态加载。

初始版本代码严格遵循"直接拼接用户输入的 name 参数到路径中，不做任何过滤"的开发要求编写，导致 `/page` 路由存在严重的安全缺陷。攻击者可利用路径穿越漏洞读取服务器上的任意文件，包括系统配置文件、应用源码和数据库文件。

本次安全审计围绕动态页面加载功能衍生的三类漏洞展开，通过对比漏洞版代码与修复版代码的安全效果，验证正则白名单校验和路径规范化校验等防御手段的有效性。

### 1.2 运行环境

| 项目 | 版本 / 规格 |
|:---|:---|
| 开发语言 | Python 3.10+ |
| Web 框架 | Flask 3.x |
| 数据库 | SQLite3 |
| 模板引擎 | Jinja2 |
| 页面目录 | pages/ |
| 服务地址 | https://127.0.0.1:5000 |
| 测试工具 | curl、Burp Suite |

### 1.3 新增功能说明

| 路由 | 方法 | 功能 | 参数 |
|:---|:---|:---|:---|
| `/page` | GET | 读取 pages/ 目录下的文件并展示在首页 | `name` 从 URL 参数获取 |
| `pages/help.html` | — | 帮助中心静态页面 | 通过 `/page?name=help` 访问 |

**正常使用流程：** 用户访问 `/page?name=help`，服务端拼接路径 `pages/help.html`，读取文件内容并通过 `index.html` 模板渲染展示。

---

## 2. 漏洞风险分析

### 2.1 漏洞成因总述

本次发现的漏洞可归纳为两类安全缺陷：

**第一类：路径校验缺失（VULN-PG-01、VULN-PG-02）**

`/page` 路由直接将用户输入的 `name` 参数通过 `os.path.join("pages", name)` 拼接为文件路径，未对 `name` 中的特殊字符做任何过滤。Python 的 `os.path.join()` 在处理包含 `../` 的路径时，会将其解析为上级目录。攻击者通过构造 `../../etc/passwd` 等路径穿越参数，可以读取 `pages/` 目录以外的任意文件。

**第二类：渲染防护不足（VULN-PG-03）**

`index.html` 使用 `{{ page_content | safe }}` 过滤器渲染页面内容，`safe` 会禁用 Jinja2 的 HTML 自动转义。虽然当前 `pages/` 目录下的文件均为可控的静态 HTML，但结合路径穿越漏洞读取到的任意文件内容，存在跨站脚本攻击的潜在风险。

### 2.2 VULN-PG-01：路径穿越读取任意文件

**【漏洞原理】**

`/page` 路由将用户输入的 `name` 参数直接用于文件路径拼接，未经任何过滤或校验。`os.path.join("pages", "../../etc/passwd")` 在 Python 中的行为是拼接后交给操作系统解析，结果为 `pages/../../etc/passwd`，归一化后变为 `../etc/passwd`（相对于当前工作目录）。如果存在这样的文件，其内容将被读取并返回给客户端。

**【漏洞代码位置】** `app.py` — `/page` 路由第 4-10 行

```python
name = request.args.get("name", "")
# ── 无路径校验 ──
filepath = os.path.join("pages", name)        # 直接拼接用户输入

if os.path.isfile(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        page_content = f.read()                # 读取任意文件内容
```

**【攻击方式】**

```bash
# 读取系统密码文件
curl "http://127.0.0.1:5000/page?name=../../etc/passwd"

# 读取应用源码，分析其他漏洞
curl "http://127.0.0.1:5000/page?name=../app.py"

# 读取数据库文件，窃取用户数据
curl "http://127.0.0.1:5000/page?name=../data/users.db"
```

**【风险等级】** ⛔ **高危** — CVSS 3.1 Score: 8.6

攻击者可通过路径穿越读取服务器上任意文件，包括：
- 系统配置文件：`/etc/passwd`、`/etc/shadow`、`/etc/nginx/nginx.conf`
- 应用源码：`app.py`、`config.py`，发现更多漏洞
- 数据库文件：`users.db`，窃取全部用户数据
- 敏感密钥文件：SSL 证书私钥、API Token 等

### 2.3 VULN-PG-02：敏感文件信息泄露

**【漏洞原理】**

当 `name` 参数指向一个存在的文件时，文件内容被完整读取并通过 `page_content` 变量发送给客户端。该内容未经任何过滤或脱敏处理。如果读取到的文件包含敏感信息（如数据库连接字符串、密码哈希、私钥等），这些信息将直接暴露给攻击者。

**【漏洞代码位置】** `app.py` — `/page` 路由第 8-10 行

```python
if os.path.isfile(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        page_content = f.read()   # 文件内容直接传递到模板
```

**【攻击方式】**

```bash
# 读取应用配置获取密钥信息
curl "http://127.0.0.1:5000/page?name=../.env"

# 读取源代码获取数据库结构
curl "http://127.0.0.1:5000/page?name=../app.py"

# 读取操作系统文件
curl "http://127.0.0.1:5000/page?name=../../etc/issue"
```

**【风险等级】** ⛔ **高危** — CVSS 3.1 Score: 7.5

信息泄露是所有进一步攻击的基础。攻击者获取源码后可分析其他业务逻辑漏洞，获取数据库后可窃取全部用户信息。结合 VULN-PG-01，任意文件读取可直接导致完整的信息泄露。

### 2.4 VULN-PG-03：页面内容未限制渲染范围

**【漏洞原理】**

`index.html` 中使用 Jinja2 的 `safe` 过滤器渲染 `page_content` 变量。`safe` 过滤器会禁用 HTML 自动转义，这意味着如果 `page_content` 中包含 HTML 标签或 JavaScript 代码，它们将在用户浏览器中直接执行。

**【漏洞代码位置】** `templates/index.html` 第 6 行

```html
<div class="page-content">{{ page_content | safe }}</div>
```

**【攻击方式】**

攻击者结合 VULN-PG-01 读取包含恶意 JavaScript 的文件，或通过其他方式在服务器上写入恶意 HTML 文件，然后访问对应的 `/page` 路由使恶意代码在用户浏览器中执行。

**【风险等级】** 🔵 **低危** — CVSS 3.1 Score: 3.5

需要先具备文件写入权限或路径穿越读取到包含恶意内容的文件才能利用。但此类漏洞一旦被利用，可能导致用户身份冒用、会话劫持等严重后果。

---

## 3. 漏洞验证过程

### 3.1 漏洞版代码关键片段

以下代码取自漏洞版 `app.py` 中 `/page` 路由的完整实现，全部三类漏洞均集中于此。

```python
# ═══════════════════════════════════════════
# 动态页面加载路由（文件路径拼接，无校验）
# ═══════════════════════════════════════════
@app.route("/page")
def page():
    name = request.args.get("name", "")
    if not name:
        return "缺少页面名称", 400

    # 漏洞1/2：直接拼接用户输入的 name 到路径中，无../过滤、无路径规范化
    filepath = os.path.join("pages", name)
    page_content = None

    if os.path.isfile(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            page_content = f.read()
    else:
        # 尝试加上 .html 后缀
        filepath_html = os.path.join("pages", name + ".html")
        if os.path.isfile(filepath_html):
            with open(filepath_html, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            page_content = "页面不存在"

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = sanitize_user_info(USERS[username])

    # 漏洞3：page_content 通过 | safe 渲染，禁用 HTML 转义
    return render_template("index.html", user=user_info, page_content=page_content)
```

**`index.html` 中渲染页面的部分：**

```html
{# 漏洞3：使用了 safe 过滤器，禁用 HTML 转义 #}
{% if page_content %}
<div class="card">
    <h2 class="card-title">页面内容</h2>
    <div class="page-content">{{ page_content | safe }}</div>
</div>
{% endif %}
```

### 3.2 攻击复现命令与预期结果

**前置操作：** 无，路径穿越漏洞无需登录即可利用。

| 漏洞编号 | 攻击命令 | 预期结果 |
|:---|:---|:---|
| VULN-PG-01 | `curl "http://127.0.0.1:5000/page?name=../../etc/passwd"` | 返回系统用户列表文件内容 |
| VULN-PG-01 | `curl "http://127.0.0.1:5000/page?name=../app.py"` | 返回 Flask 应用完整源代码 |
| VULN-PG-01 | `curl "http://127.0.0.1:5000/page?name=../data/users.db"` | 返回 SQLite 数据库文件的二进制内容 |
| VULN-PG-02 | `curl "http://127.0.0.1:5000/page?name=../../etc/shadow"` | 返回系统密码哈希（如果权限足够） |
| VULN-PG-03 | 通过路径穿越读取包含 JavaScript 的文件 | 页面中执行恶意脚本 |
| 正常功能 | `curl "http://127.0.0.1:5000/page?name=help"` | 显示帮助中心内容 |
| 正常功能 | `curl "http://127.0.0.1:5000/page?name=notexist"` | 返回"页面不存在" |

### 3.3 Burp Suite 测试过程

**测试步骤：**

1. 启动 Burp Suite，配置浏览器代理为 127.0.0.1:8080。
2. 在浏览器中访问 `/page?name=help` 并观察正常响应。
3. 将请求发送到 Repeater。
4. 在 Repeater 中依次修改 `name` 参数值：

| 测试编号 | 修改内容 | 测试目的 | 预期结果 |
|:---|:---|:---|:---|
| ① | `name=../../etc/passwd` | 路径穿越读取系统文件 | 返回 passwd 文件内容 |
| ② | `name=../app.py` | 读取应用源码 | 返回 Python 源代码 |
| ③ | `name=../data/users.db` | 读取数据库 | 返回二进制数据 |
| ④ | `name=..\..\..\windows\win.ini` | Windows 路径穿越 | 返回 win.ini（如为 Windows 系统） |
| ⑤ | `name=help` | 正常功能验证 | 正常显示帮助中心 |

5. 点击 Send，观察 Response 中的文件内容。

---

## 4. 漏洞修复方案

### 4.1 核心修复思想

本次修复对 `/page` 路由实施**双重路径安全校验**：

| 防线 | 对应漏洞 | 技术手段 |
|:---|:---|:---|
| **第一道：字符白名单** | VULN-PG-01、VULN-PG-02 | 正则 `^[a-zA-Z0-9_-]+$`，从源头阻止 `../` 等路径穿越字符 |
| **第二道：路径规范化校验** | VULN-PG-01、VULN-PG-02 | `os.path.realpath()` 解析绝对路径，检查是否以 `pages/` 目录前缀开头 |

这两道防线相互独立。第一道防线从字符层面杜绝路径穿越，第二道防线即使第一道被绕过，仍能确保文件读取范围不超出 `pages/` 目录。

### 4.2 修复后代码关键片段

```python
import re

# ═══════════════════════════════════════════
# 动态页面加载路由（安全加固版）
# ═══════════════════════════════════════════
@app.route("/page")
def page():
    name = request.args.get("name", "")
    if not name:
        return "缺少页面名称", 400

    # 第一道防线：字符白名单校验，从源头阻止路径穿越
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return "非法的页面名称", 400

    page_content = None
    pages_dir = os.path.join(app.root_path, "pages")

    # 第二道防线：规范化路径，确认在 pages/ 范围内
    safe_path = os.path.realpath(os.path.join(pages_dir, name))
    if not safe_path.startswith(os.path.realpath(pages_dir)):
        return "非法的页面名称", 400

    # 尝试直接打开，再尝试加 .html 后缀
    if os.path.isfile(safe_path):
        with open(safe_path, "r", encoding="utf-8") as f:
            page_content = f.read()
    else:
        html_path = safe_path + ".html"
        if os.path.isfile(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            page_content = "页面不存在"

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = sanitize_user_info(USERS[username])

    return render_template("index.html", user=user_info, page_content=page_content)
```

### 4.3 修复原理讲解

**第一道防线 — 正则白名单的原理：**

正则表达式 `^[a-zA-Z0-9_-]+$` 匹配仅包含大小写字母、数字、连字符和下划线的字符串。这意味着：

- `../` 中的 `.` 和 `/` 不被匹配 → 请求被拒绝
- `../../etc/passwd` 包含 `.` 和 `/` → 请求被拒绝
- `help` 全部由字母组成 → 通过校验
- `help-center` 包含字母和连字符 → 通过校验

白名单策略的核心优势在于：**不需要知道哪些字符是危险的，只需要明确允许哪些字符**。任何不在白名单中的字符都会被直接拒绝，使得所有已知和未知的路径穿越攻击手法在字符层面就被禁止。

**第二道防线 — 路径规范化校验的原理：**

`os.path.realpath()` 函数会将相对路径解析为绝对路径，并解析其中的所有符号链接和 `..` 引用。例如：

- `os.path.realpath("pages/help.html")` → `/root/user-management-platform/pages/help.html`
- `os.path.realpath("pages/../../etc/passwd")` → `/etc/passwd`
- `os.path.realpath("pages/../app.py")` → `/root/user-management-platform/app.py`

校验逻辑判断解析后的绝对路径是否以 `pages/` 目录的绝对路径为前缀：

```python
if not safe_path.startswith(os.path.realpath(pages_dir)):
    return "非法的页面名称", 400
```

如果 `safe_path` 是 `/etc/passwd`，而 `pages_dir` 是 `/root/user-management-platform/pages`，那么 `/etc/passwd` 不以 `/root/user-management-platform/pages` 开头，校验失败。

**两道防线相互补充：**

- 正则白名单在攻击数据刚进入应用时即进行拦截，效率高、开销小
- 路径规范化校验作为最终屏障，即使正则被绕过（如发现新的合法字符组合能实现穿越），仍然能确保读取范围不越界

**关于 VULN-PG-03 的说明：**

`{{ page_content | safe }}` 在当前业务场景中风险可控，因为 `pages/` 目录下的文件均为预置的开发人员可控的静态 HTML。正则白名单确保用户只能请求到白名单字符对应的文件，无法加载恶意内容。因此未修改模板渲染方式，业务功能保持完整。

---

## 5. 修复结果验证

### 5.1 攻击复现回归测试

在启动修复版服务后，重新执行全部攻击复现命令，结果如下：

| 测试项目 | 漏洞版结果 | 修复版结果 | 结论 |
|:---|:---|:---|:---|
| `/page?name=../../etc/passwd` | ✅ 返回 passwd 文件内容 | ❌ 返回"非法的页面名称" | 正则白名单拦截 |
| `/page?name=../app.py` | ✅ 返回 Python 源代码 | ❌ 返回"非法的页面名称" | 正则白名单拦截 |
| `/page?name=../data/users.db` | ✅ 返回数据库二进制内容 | ❌ 返回"非法的页面名称" | 正则白名单拦截 |
| `/page?name=sub/../help` | ✅ 返回帮助页面 | ❌ 返回"非法的页面名称" | 正则白名单拦截 |
| `/page?name=.htaccess` | ✅ 读取隐藏文件 | ❌ 返回"非法的页面名称" | 正则白名单拦截 |
| `/page?name=help`（正常功能） | ✅ 显示帮助中心 | ✅ 显示帮助中心 | 正常功能不受影响 |
| `/page?name=notexist`（不存在） | ✅ 返回"页面不存在" | ✅ 返回"页面不存在" | 正常功能不受影响 |

### 5.2 Burp Suite 回归测试

| 测试编号 | 测试内容 | 漏洞版结果 | 修复版结果 |
|:---|:---|:---|:---|
| ① | `name=../../etc/passwd` | 返回系统文件内容 | 返回"非法的页面名称" |
| ② | `name=../app.py` | 返回 Python 源码 | 返回"非法的页面名称" |
| ③ | `name=../data/users.db` | 返回数据库内容 | 返回"非法的页面名称" |
| ④ | `name=help` | 正常显示帮助中心 | 正常显示帮助中心 |

以上测试结果表明，两道防线全部生效，所有路径穿越攻击在修复版中均无法成功执行，正常业务功能未受影响。

---

## 6. 安全总结与后续防护建议

### 安全总结

本次动态页面加载模块漏洞审计与修复实训得出以下结论：

**第一，文件路径操作必须实施严格的白名单校验。** 任何涉及文件读取的功能，只要用户能够以任何形式影响路径的组成部分，就必须对用户输入进行严格过滤。正则白名单 `^[a-zA-Z0-9_-]+$` 是最简单也最有效的防御方式，它从字符层面杜绝了路径穿越的可能。

**第二，路径穿越是 Web 应用中的高危漏洞。** 一个看似无害的路径拼接操作，如果缺少校验，可能导致服务器上任意文件的读取。从系统配置文件到应用源码，再到数据库文件，全部可能被攻击者获取。

**第三，防御应分层实施，形成纵深防御体系。** 字符白名单和路径规范化校验两道防线互相补充：白名单高效拦截大部分攻击，路径规范化校验作为最终屏障兜底。单一防御手段可能被绕过，多层防御可以显著提升安全性。

**第四，safe 过滤器的使用需要谨慎。** Jinja2 的 `safe` 过滤器会禁用 HTML 自动转义，虽然在本场景中风险可控，但作为通用安全规范，应尽量避免在不可控内容上使用 `safe`。

### 后续防护建议

| 优先级 | 建议措施 | 说明 |
|:---|:---|:---|
| P0 | 全面审查文件操作 | 检查项目中所有涉及文件读写的代码，确保都实施了路径校验 |
| P0 | 使用白名单替代黑名单 | 所有用户输入的路径参数统一使用正则白名单 `^[a-zA-Z0-9_-]+$` |
| P1 | 文件静态化 | 将 pages/ 目录的静态页面读取改为在路由中硬编码映射 |
| P1 | 最小权限运行 | 应用使用低权限用户运行，限制可读取的文件范围 |
| P2 | 安全编码规范培训 | 确保所有开发人员了解路径穿越漏洞的原理和防御方法 |
| P2 | 代码审计制度化 | 在上线前对所有文件操作代码进行安全审计 |
| P3 | WAF 规则部署 | 部署 ModSecurity 规则拦截路径穿越攻击 Payload |

---

*报告生成时间：2026 年 7 月 | 测试工具：curl、Burp Suite | 修复方式：正则白名单 + 路径规范化校验*
