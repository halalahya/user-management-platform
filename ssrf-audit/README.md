# URL 抓取功能模块 — 安全审计与修复

## 项目总览

本项目基于 Flask + SQLite3 开发，提供了用户登录、注册、搜索、头像上传、个人中心、充值、动态页面加载等功能。本次新增了 **URL 抓取功能**，允许已登录用户输入 URL，服务端通过 `urllib.request.urlopen()` 抓取目标地址内容并返回结果。

初始版本未对 URL 做任何限制，存在 SSRF 漏洞。本模块对该功能进行专项安全审计，共发现 3 项安全漏洞，并逐一实施修复。

## 环境部署

```bash
# 安装依赖
pip install flask

# 启动漏洞版
cd ssrf-audit/vulnerable
python app.py

# 启动修复版
cd ssrf-audit/fixed
python app.py

# 访问地址
https://127.0.0.1:5000

# 默认账号
admin / admin123
```

## 目录结构

```
ssrf-audit/
├── 1-SECURITY_AUDIT.md              # 安全审计报告
├── vulnerable/                       # 漏洞原版代码
│   ├── app.py                       # 含 SSRF 漏洞的完整后端
│   └── index.html                   # 含 URL 抓取界面的首页
├── fixed/                           # 修复版代码
│   ├── app.py                       # 安全加固后的完整后端
│   └── index.html                   # 修复后的首页
└── README.md                        # 本文件
```

---

## 漏洞模块

### VULN-SSRF-01：协议未限制致任意文件读取

**漏洞原理：** `urlopen()` 支持 `file://` 等本地协议，攻击者可通过构造 `file:///etc/passwd` 读取服务器任意文件。

**原始代码：**
```python
resp = urllib.request.urlopen(url, timeout=10)
```

**复现步骤：**
```bash
curl -X POST -d "url=file:///etc/passwd" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
```

---

### VULN-SSRF-02：内网地址未限制致 SSRF 攻击

**漏洞原理：** 未对目标 IP 做内网校验，攻击者可扫描内网端口、访问云元数据接口。

**复现步骤：**
```bash
# 扫描本地端口
curl -X POST -d "url=http://127.0.0.1:5000" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
```

---

### VULN-SSRF-03：URL 及端口未校验致资源扫描

**漏洞原理：** 未校验 URL 格式和端口范围，攻击者可实施端口探测。

**复现步骤：**
```bash
curl -X POST -d "url=http://192.168.1.1:22" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
```

---

## 安全修复方案

| 漏洞 | 修复方式 |
|------|---------|
| VULN-SSRF-01 任意文件读取 | 协议白名单，仅允许 `http://` 和 `https://` |
| VULN-SSRF-02 内网 SSRF | IP 黑名单：回环地址、私有网段、云元数据地址 |
| VULN-SSRF-03 端口扫描 | URL 格式校验 + 端口范围限制（1-65535） |

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

# 内网IP拦截
try:
    ip = socket.gethostbyname(parsed.hostname)
except socket.gaierror:
    return "无法解析域名", 400
if _is_private_ip(ip):
    return "不允许访问内网地址", 400
```

---

## 功能使用说明

修复版支持抓取外部合法 HTTP/HTTPS 网站内容：

```bash
# 抓取外部网站
curl -X POST -d "url=https://example.com" \
  -b "session=..." \
  https://127.0.0.1:5000/fetch-url

# 抓取失败示例（file:// 被拦截）
curl -X POST -d "url=file:///etc/passwd" \
  -b "session=..." \
  https://127.0.0.1:5000/fetch-url
# 返回：不支持的协议，仅允许 http:// 和 https://

# 抓取失败示例（内网被拦截）
curl -X POST -d "url=http://127.0.0.1:5000" \
  -b "session=..." \
  https://127.0.0.1:5000/fetch-url
# 返回：不允许访问内网地址
```

## 开发说明

```
app.py 中 /fetch-url 路由相关代码结构：

fetch_url()          — 主路由处理函数
  ├─ 登录校验       — session 检查
  ├─ 协议白名单     — http/https 校验
  ├─ URL 格式校验   — urlparse 解析
  ├─ 端口范围校验   — 1-65535 检查
  ├─ 内网 IP 拦截   — socketa gethostbyname
  ├─ urlopen 抓取   — 实际 HTTP 请求
  └─ 结果返回       — 状态码 + 内容

_is_private_ip()    — 内网 IP 检测辅助函数
  ├─ 127.0.0.0/8   回环地址
  ├─ 10.0.0.0/8    私有 A 类
  ├─ 169.254.0.0/16 链路本地
  ├─ 172.16.0.0/12 私有 B 类
  ├─ 192.168.0.0/16 私有 C 类
  ├─ 0.0.0.0/8     默认路由
  └─ ::1           IPv6 回环
```
