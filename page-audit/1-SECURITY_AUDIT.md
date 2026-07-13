# 动态页面加载模块安全审计报告

**审计范围：** Flask用户管理系统 — `/page` GET路由、pages/目录动态文件读取  
**审计日期：** 2026年7月  
**漏洞数量：** 共发现 **3 项安全漏洞**

---

## 漏洞总览

| 编号 | 漏洞名称 | 触发位置 | 风险等级 |
|------|---------|---------|---------|
| VULN-PG-01 | 路径穿越读取任意文件 | `/page` 路由第449-451行 | 高危 |
| VULN-PG-02 | 敏感文件信息泄露 | `/page` 路由第454-461行 | 高危 |
| VULN-PG-03 | 页面内容未限制渲染范围 | `index.html` 第70-71行 | 低危 |

---

## 漏洞详情

### VULN-PG-01：路径穿越读取任意文件

**漏洞原理：** `/page` 路由直接将用户输入的 `name` 参数与 `"pages"` 字符串拼接成文件路径，未对 `../` 等路径穿越字符做任何过滤。攻击者可通过构造 `../../etc/passwd` 等路径穿越参数，读取服务器上任意位置的文件内容。

**漏洞代码位置：** `app.py` 第449-451行

```python
name = request.args.get("name", "")
# 直接拼接用户输入的 name 到路径中，无任何过滤
filepath = os.path.join("pages", name)
if os.path.isfile(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        page_content = f.read()
```

**漏洞利用分析：** `os.path.join("pages", "../../etc/passwd")` 在 Python 中的行为是将路径拼接后交给操作系统解析。在绝大多数文件系统上，`pages/../../etc/passwd` 归一化为 `../etc/passwd`（相对于当前工作目录），最终解析为 `/etc/passwd`。文件内容被读取后通过 `page_content` 变量传入模板并渲染到页面中。

**复现 POC：**
```bash
# 读取系统密码文件
curl "http://127.0.0.1:5000/page?name=../../etc/passwd"

# 读取应用配置文件
curl "http://127.0.0.1:5000/page?name=../../app.py"

# 读取数据库文件
curl "http://127.0.0.1:5000/page?name=../../data/users.db"
```

**风险等级：** 高危 CVSS 3.1 Score: 8.6

攻击者可通过路径穿越读取服务器上任意文件，包括但不限于：
- 系统配置文件（`/etc/passwd`、`/etc/shadow`）
- 应用源码（`app.py`），发现更多漏洞
- 数据库文件（`users.db`），窃取全部用户数据
- 敏感密钥文件（SSL证书私钥）

---

### VULN-PG-02：敏感文件信息泄露

**漏洞原理：** 当 `name` 参数指向一个存在的文件时，文件内容被完整读取并发送给客户端。该文件的内容未经任何过滤或脱敏处理，如果读取到包含敏感信息的文件（如数据库文件、配置文件），这些信息将直接暴露给攻击者。

**漏洞代码位置：** `app.py` 第453-461行

```python
if os.path.isfile(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        page_content = f.read()   # 文件内容直接传递给模板
```

**复现 POC：**
```bash
# 读取 Python 源码，获取数据库结构和密码策略
curl "http://127.0.0.1:5000/page?name=../app.py"

# 读取帮助页面源码
curl "http://127.0.0.1:5000/page?name=../pages/help.html"
```

**风险等级：** 高危 CVSS 3.1 Score: 7.5

信息泄露是所有进一步攻击的基础。攻击者获取源码后可分析其他漏洞，获取数据库后可窃取全部用户信息。

---

### VULN-PG-03：页面内容未限制渲染范围

**漏洞原理：** `index.html` 中使用 `{{ page_content | safe }}` 渲染页面内容。`safe` 过滤器禁用 Jinja2 的 HTML 自动转义，如果读取的文件内容包含 HTML 或 JavaScript 代码，这些代码将在用户浏览器中直接执行。

**漏洞代码位置：** `templates/index.html` 第70行

```html
<div class="page-content">{{ page_content | safe }}</div>
```

**风险等级：** 低危 CVSS 3.1 Score: 3.5

由于 `page_content` 的内容来自服务器上的静态文件，攻击者需要先具备文件写入权限才能利用此漏洞。但结合 VULN-PG-01 读取到的恶意文件内容，仍然存在 XSS 风险。

---

## 修复方案

### 修复方式：路径白名单 + 路径合法性校验

在保留原有业务逻辑的前提下，对 `name` 参数增加两层校验：

1. **白名单字符限制：** 只允许 `name` 参数包含字母、数字、连字符和下划线，从源头杜绝 `../` 等路径穿越字符的传入。
2. **解析后路径校验：** 使用 `os.path.realpath()` 将拼接后的路径解析为绝对路径，并检查其是否以 `pages/` 目录的绝对路径为前缀，确保读取的文件一定在允许范围内。

**修复后的核心逻辑：**

```python
import re

@app.route("/page")
def page():
    name = request.args.get("name", "")
    if not name:
        return "缺少页面名称", 400

    # 修复：白名单校验 — 只允许字母、数字、连字符、下划线
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return "非法的页面名称", 400

    # 修复：使用安全路径拼接 + 规范化校验
    pages_dir = os.path.join(app.root_path, "pages")
    safe_path = os.path.realpath(os.path.join(pages_dir, name))

    if not safe_path.startswith(os.path.realpath(pages_dir)):
        return "非法的页面名称", 400

    for ext in ["", ".html"]:
        target = safe_path + ext
        if os.path.isfile(target):
            with open(target, "r", encoding="utf-8") as f:
                page_content = f.read()
                return render_template("index.html", user=user_info, page_content=page_content)

    page_content = "页面不存在"
    return render_template("index.html", user=user_info, page_content=page_content)
```

### 漏洞修复对照表

| 漏洞 | 修复方式 | 说明 |
|------|---------|------|
| VULN-PG-01 路径穿越 | `re.match()` 白名单 + `os.path.realpath()` 校验 | `../` 无法通过白名单，路径穿越彻底失效 |
| VULN-PG-02 敏感文件泄露 | 路径限制在 `pages/` 目录范围内 | 无法读取 pages 目录外的任何文件 |
| VULN-PG-03 渲染范围 | 白名单间接限制，pages 目录内均为安全静态页面 | 仅允许读取预置的页面文件 |
