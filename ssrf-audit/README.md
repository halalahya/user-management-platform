# URL 抓取功能模块 — 安全审计与修复

## 项目总览

本项目基于 Flask + SQLite3 开发，提供了用户登录、注册、搜索、头像上传、个人中心、充值、动态页面加载等功能。本次新增了 **URL 抓取功能**，允许已登录用户输入 URL，服务端通过 `urllib.request.urlopen()` 抓取目标地址内容并返回结果。

初始版本未对 URL 做任何限制，存在 SSRF 漏洞。本模块对该功能进行专项安全审计，共发现 3 项安全漏洞，并逐一实施修复。

## 运行环境

| 项目 | 版本 |
|:---|:---|
| Python | 3.10+ |
| Flask | 3.x |
| 数据库 | SQLite3 |
| 网络请求 | urllib.request |

## 环境部署

```bash
pip install flask

# 启动漏洞版
cd ssrf-audit/vulnerable && python app.py

# 启动修复版
cd ssrf-audit/fixed && python app.py

# 访问地址 https://127.0.0.1:5000
# 默认账号 admin / admin123
```

## 目录结构

```
ssrf-audit/
├── 1-SECURITY_AUDIT.md          # 安全审计报告
├── vulnerable/                   # 漏洞原版代码
│   ├── app.py                   # 含 SSRF 漏洞的完整后端
│   └── index.html               # 含 URL 抓取界面的首页
├── fixed/                       # 修复版代码
│   ├── app.py                   # 安全加固后的完整后端
│   └── index.html               # 修复后的首页
└── README.md                    # 本文件
```

---

## 漏洞模块

### VULN-SSRF-01：协议未限制致任意文件读取（高危）

**漏洞成因：** `urllib.request.urlopen()` 支持 `file://` 等本地协议。代码未对 url 参数做协议白名单限制，攻击者可构造 `file:///etc/passwd` 读取任意文件。

**漏洞代码：**
```python
url = request.form.get("url", "")
resp = urllib.request.urlopen(url, timeout=10)  # 支持 file:// 协议
```

**复现方式：**
```bash
# 读取系统密码文件
curl -X POST -d "url=file:///etc/passwd" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
# 读取应用源码
curl -X POST -d "url=file:///path/to/app.py" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
```

**风险等级：** ⛔ 高危 — CVSS 8.6

---

### VULN-SSRF-02：内网地址未限制致 SSRF 攻击（高危）

**漏洞成因：** 未对目标 IP 做内网校验，攻击者可访问 127.0.0.1、10.x.x.x、169.254.169.254 等内网地址。

**漏洞代码：**
```python
url = request.form.get("url", "")
resp = urllib.request.urlopen(url, timeout=10)  # 可访问内网
```

**复现方式：**
```bash
# 扫描本地端口
curl -X POST -d "url=http://127.0.0.1:5000" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
# 访问云元数据接口
curl -X POST -d "url=http://169.254.169.254/latest/meta-data/" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
```

**风险等级：** ⛔ 高危 — CVSS 8.2

---

### VULN-SSRF-03：URL 及端口未校验致资源扫描（中危）

**漏洞成因：** 未校验 URL 格式和端口范围，攻击者可对内外网进行端口探测。

**复现方式：**
```bash
curl -X POST -d "url=http://192.168.1.1:22" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
```

**风险等级：** ⚠️ 中危 — CVSS 5.3

---

## 安全修复方案

| 漏洞 | 修复方式 | 修复效果 |
|:---|:---|:---|
| VULN-SSRF-01 任意文件读取 | 协议白名单，仅允许 http/https | `file:///etc/passwd` → "不支持的协议" |
| VULN-SSRF-02 内网 SSRF | IP 黑名单检测（回环/私有/云元数据） | `127.0.0.1` → "不允许访问内网地址" |
| VULN-SSRF-03 端口扫描 | URL 格式校验 + 端口范围限制 | 畸形 URL/端口 → "无效" |

### 修复代码关键片段

```python
# 协议白名单
if not url.startswith("http://") and not url.startswith("https://"):
    return "不支持的协议，仅允许 http:// 和 https://", 400

# URL 格式校验
from urllib.parse import urlparse
parsed = urlparse(url)
if not parsed.hostname:
    return "无效的 URL 格式", 400

# 端口校验
port = parsed.port
if port is not None and (port < 1 or port > 65535):
    return "无效的端口号", 400

# 内网 IP 拦截
_ip = socket.gethostbyname(parsed.hostname)
if _is_private_ip(ip):
    return "不允许访问内网地址", 400
```

### 内网 IP 检测函数

```python
def _is_private_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4: return True
    first = int(parts[0])
    if first == 127: return True           # 127.0.0.0/8
    if first == 10: return True            # 10.0.0.0/8
    if first == 169 and int(parts[1]) == 254: return True  # 169.254.0.0/16
    if first == 172 and 16 <= int(parts[1]) <= 31: return True  # 172.16.0.0/12
    if first == 192 and int(parts[1]) == 168: return True  # 192.168.0.0/16
    if first == 0: return True             # 0.0.0.0/8
    if ip == "::1": return True            # IPv6 回环
    return False
```

## 修复前后对比

| 测试项 | 漏洞版 | 修复版 |
|:---|:---|:---|
| `file:///etc/passwd` | ✅ 读取成功 | ❌ "不支持的协议" |
| `http://127.0.0.1:5000` | ✅ 访问成功 | ❌ "不允许访问内网地址" |
| `http://192.168.1.1:80` | ✅ 尝试连接 | ❌ "不允许访问内网地址" |
| `http://example.com` | ✅ 状态码 200 | ✅ 状态码 200 |
| 畸形 URL | 执行报错 | ❌ "无效的 URL 格式" |

## 功能使用说明

```bash
# 抓取外部网站（修复版支持）
curl -X POST -d "url=https://example.com" -b "session=..." \
  https://127.0.0.1:5000/fetch-url

# file:// 被拦截
curl -X POST -d "url=file:///etc/passwd" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
# 返回：不支持的协议

# 内网被拦截
curl -X POST -d "url=http://127.0.0.1:5000" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
# 返回：不允许访问内网地址
```

## 免责声明

本仓库提供的漏洞代码和 POC 测试命令仅用于 **网络安全教学与合法授权测试**。禁止用于未经授权的系统测试或攻击，任何非法使用造成的法律后果由使用者自行承担。请遵守《中华人民共和国网络安全法》及相关法律法规。
