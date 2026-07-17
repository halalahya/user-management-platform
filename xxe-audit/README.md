# XML 数据导入功能模块 — 安全审计与修复

## 项目总介绍

本项目基于 Flask + SQLite3 开发，提供用户登录、注册、搜索、头像上传、个人中心、充值、动态页面加载、URL 抓取、Ping 测试、密码修改等功能。本次新增了 **XML 数据导入功能**，允许已登录用户提交 XML 格式的数据，系统解析后提取用户信息并以 JSON 格式返回。

初始版本实现了自定义的 XXE 实体解析逻辑，检测 `<!ENTITY ... SYSTEM "file://..."` 定义后直接读取本地文件，存在严重的 XML 外部实体注入漏洞。本模块对该功能进行专项安全审计，共发现 2 项典型安全漏洞，并逐一实施修复。

## 运行环境

| 项目 | 版本 |
|:---|:---|
| Python | 3.10+ |
| Flask | 3.x |
| 数据库 | SQLite3 |
| XML 解析 | xml.etree.ElementTree |

## XML 导入功能业务说明

| 项目 | 说明 |
|:---|:---|
| 路由 | `GET /xml-import` 显示页面；`POST /xml-import` 解析 XML |
| 参数 | `xml_data` — XML 字符串 |
| 响应 | JSON 格式解析结果（提取 user 节点的 name 和 email） |
| 漏洞版 | 自定义 `resolve_xxe()` 函数，检测 ENTITY/SYSTEM 后读取本地文件 |
| 修复版 | 禁止 DOCTYPE 声明，使用解析器默认配置 |

## 环境部署

```bash
pip install flask
cd 项目目录
python app.py
# 访问 https://127.0.0.1:5000
# 默认账号 admin / admin123
```

## 目录结构

```
xxe-audit/
├── 1-SECURITY_AUDIT.md        # 安全审计报告
├── vulnerable/                # 漏洞原版代码
│   ├── app.py                # 含 XXE 漏洞的完整后端
│   └── xml_import.html       # XML 导入页面模板
├── fixed/                    # 修复版代码
│   ├── app.py                # 修复后的完整后端
│   └── xml_import.html       # 修复后的页面模板
└── README.md                 # 本文件
```

---

## XML 模块完整漏洞审计报告

### VULN-XXE-01：XML 外部实体注入任意文件读取（高危）

| 项目 | 内容 |
|:---|:---|
| **风险等级** | ⛔ 高危 — CVSS 8.6 |
| **漏洞成因** | resolve_xxe() 函数检测到 `<!ENTITY ... SYSTEM "file://..."` 后，提取文件路径并用 `open()` 读取本地文件，替换到实体引用中。未对文件路径做任何白名单校验 |
| **漏洞代码** | `file_path = file_uri.replace("file://", "")` → `open(file_path).read()` |
| **利用 Payload** | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` → `&xxe;` 在 XML 中被替换为文件内容 |
| **危害说明** | 攻击者可读取服务器任意文件（系统配置、应用源码、数据库文件、SSL 私钥），导致敏感信息泄露 |

**复现方式：**
```bash
curl -X POST --data-urlencode 'xml_data=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><user name="x"><email>&xxe;</email></user></root>' \
  -b "session=..." https://127.0.0.1:5000/xml-import
```

### VULN-XXE-02：XXE 联合 SSRF 内网探测（中危）

| 项目 | 内容 |
|:---|:---|
| **风险等级** | ⚠️ 中危 — CVSS 6.5 |
| **漏洞成因** | SYSTEM 标识符不仅支持 file://，也支持 http://，攻击者可利用 XXE 发起服务端 HTTP 请求探测内网服务 |
| **利用 Payload** | `<!ENTITY xxe SYSTEM "http://127.0.0.1:5000">` |
| **危害说明** | 攻击者可将服务器作为跳板探测内网端口和服务，绕过防火墙限制 |

---

## 逐条漏洞修复方案

### 修复 VULN-XXE-01/02：禁止 DOCTYPE 声明

**修复思路：** 直接删除自定义的 `resolve_xxe()` 函数，在解析 XML 前检测 `<!DOCTYPE` 和 `<!ENTITY` 关键字，发现即拦截返回错误。XML 解析器 `ET.fromstring()` 默认不解析外部实体，配合 DOCTYPE 拦截，从源头上阻断 XXE 攻击。

**修复前（漏洞版）：**
```python
def resolve_xxe(content):
    for match in re.finditer(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"', content):
        file_uri = match.group(2)
        file_path = file_uri.replace("file://", "")
        with open(file_path, "r") as f:
            file_content = f.read()
        content = content.replace(f"&{entity_name};", file_content)
    return content

resolved_xml = resolve_xxe(xml_data)
root = ET.fromstring(resolved_xml)
```

**修复后（安全版）：**
```python
if "<!DOCTYPE" in xml_data.upper() or "<!ENTITY" in xml_data.upper():
    result = json.dumps({"error": "XML 中不允许包含 DOCTYPE 或 ENTITY 声明"})
else:
    try:
        root = ET.fromstring(xml_data)
        # ... 正常解析 user 节点
```

**修复效果：**
| 测试项 | 漏洞版 | 修复版 |
|:---|:---|:---|
| 正常 XML `<user name="张三">` | ✅ 正常解析 | ✅ 正常解析 |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | ✅ 读取文件内容 | ❌ "不允许包含 DOCTYPE" |
| `<!ENTITY xxe SYSTEM "http://127.0.0.1">` | ✅ 发起 HTTP 请求 | ❌ "不允许包含 DOCTYPE" |

## 页面访问操作指南

### 正常使用流程

1. 使用 `admin / admin123` 登录系统
2. 点击导航栏的 **XML导入** 链接
3. 在文本框中输入合法 XML：
```xml
<root>
  <user name="张三">
    <email>zhangsan@example.com</email>
  </user>
  <user name="李四">
    <email>lisi@example.com</email>
  </user>
</root>
```
4. 点击 **导入** 按钮，页面返回 JSON 格式解析结果

### 漏洞版测试（XXE 注入）

```bash
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt
curl -b /tmp/cookies.txt --data-urlencode \
  'xml_data=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><user name="x"><email>&xxe;</email></user></root>' \
  http://127.0.0.1:5000/xml-import
```

### 修复版验证

```bash
curl -b /tmp/cookies.txt --data-urlencode \
  'xml_data=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><user name="x"><email>&xxe;</email></user></root>' \
  http://127.0.0.1:5000/xml-import
# 返回：{"error": "XML 中不允许包含 DOCTYPE 或 ENTITY 声明"}
```

## 免责声明

本仓库提供的漏洞代码和 POC 测试命令仅用于 **网络安全教学与合法授权测试**。禁止用于未经授权的系统测试或攻击，任何非法使用造成的法律后果由使用者自行承担。请遵守《中华人民共和国网络安全法》及相关法律法规。
