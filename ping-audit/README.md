# Ping 网络诊断功能模块 — 安全审计与修复

## 项目整体介绍

本项目基于 Flask + SQLite3 开发，提供用户登录、注册、搜索、头像上传、个人中心、充值、动态页面加载、URL 抓取等功能。本次新增了 **Ping 网络诊断功能**，允许已登录用户对指定的 IP 或域名执行 Ping 操作，用于网络连通性测试。

初始版本存在命令注入漏洞，攻击者可利用 shell 拼接执行任意系统命令。本模块对该功能进行专项安全审计，共发现 2 项典型安全漏洞，并逐一实施修复。

## 运行环境

| 项目 | 版本 |
|:---|:---|
| Python | 3.10+ |
| Flask | 3.x |
| 数据库 | SQLite3 |
| 系统命令 | ping（系统自带） |

## Ping 功能设计说明

| 项目 | 说明 |
|:---|:---|
| 路由 | `GET /ping` 显示页面；`POST /ping` 执行 Ping |
| 前端 | 黑色背景绿色文字控制台风格输出区域 |
| 参数 | `ip` — IP 地址或域名 |
| 漏洞版 | `f"ping -c 3 {ip}"` + `shell=True` |
| 修复版 | `["ping", "-c", "3", ip]` + 参数列表 |

## 部署启动

```bash
pip install flask
cd 项目目录
python app.py
# 访问 https://127.0.0.1:5000
# 默认账号 admin / admin123
```

## 目录结构

```
ping-audit/
├── 1-SECURITY_AUDIT.md        # 安全审计报告
├── vulnerable/                # 漏洞原版代码
│   ├── app.py
│   ├── ping.html
│   ├── base.html
│   └── index.html
├── fixed/                    # 修复版代码
│   ├── app.py
│   ├── ping.html
│   ├── base.html
│   └── index.html
└── README.md                 # 本文件
```

---

## Ping 模块漏洞汇总报告

### VULN-PING-01：操作系统命令注入（高危）

| 项目 | 内容 |
|:---|:---|
| **风险等级** | ⛔ 高危 — CVSS 9.8 |
| **漏洞成因** | `f"ping -c 3 {ip}"` 字符串拼接 + `shell=True`，攻击者可在 ip 中注入 `;id`、`\|whoami` 等 shell 命令 |
| **利用 Payload** | `127.0.0.1;whoami`、`8.8.8.8;cat /etc/passwd`、`127.0.0.1\|id`、`8.8.8.8&&ls` |
| **漏洞代码** | `cmd = f"ping -c 3 {ip}"` → `subprocess.check_output(cmd, shell=True)` |
| **危害说明** | 攻击者可在服务器上执行任意系统命令，读取敏感文件、创建后门账号、发起内网攻击，以当前用户权限完全控制服务器 |

**复现方式：**
```bash
curl -X POST -d "ip=127.0.0.1;whoami" -b "session=..." http://127.0.0.1:5000/ping
curl -X POST -d "ip=8.8.8.8;cat /etc/passwd" -b "session=..." http://127.0.0.1:5000/ping
```

---

### VULN-PING-02：执行结果直接回显（中危）

| 项目 | 内容 |
|:---|:---|
| **风险等级** | ⚠️ 中危 — CVSS 5.3 |
| **漏洞成因** | 命令执行结果未经过滤直接渲染到页面，配合命令注入可放大攻击效果 |
| **漏洞代码** | `result = output.decode("utf-8", errors="replace")` |
| **危害说明** | 注入命令的输出结果被格式化展示，便于攻击者直接读取敏感信息 |

---

## 漏洞逐一修复方案

### 修复 VULN-PING-01：命令注入

**修复方式：** 双重重保——IP 地址白名单正则校验 + 禁用 shell=True + 使用参数列表。

**修复前（漏洞版）：**
```python
cmd = f"ping -c 3 {ip}"
output = subprocess.check_output(cmd, shell=True, timeout=30)
```

**修复后（安全版）：**
```python
import re
ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'              # IPv4
domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'

if not re.match(ip_pattern, ip) and not re.match(domain_pattern, ip):
    result = "无效的 IP 地址或域名格式"
else:
    output = subprocess.check_output(["ping", "-c", "3", ip], timeout=30)  # 无 shell=True
```

**修复原理：** 正则白名单仅允许合法 IP 或域名格式。`;`、`|`、`&`、`` ` `` 等 shell 特殊字符无法通过校验。同时禁用 `shell=True` 改用参数列表形式，ip 仅作为 ping 程序的普通参数字符串传递，不经过 shell 解析。

---

### 修复 VULN-PING-02：执行结果过滤

**修复方式：** 仅提取 Ping 命令的标准输出中与网络诊断相关的关键信息行。

**修复前（漏洞版）：**
```python
result = output.decode("utf-8", errors="replace")
```

**修复后（安全版）：**
```python
raw = output.decode("utf-8", errors="replace")
lines = raw.split("\n")
filtered = [l for l in lines if "bytes from" in l or "statistics" in l or 
            "packet loss" in l or "rtt" in l or "time=" in l]
result = "\n".join(filtered) if filtered else raw
```

**修复原理：** 通过关键词过滤，只保留 Ping 命令特有的统计信息行（延迟、丢包率）。注入命令的输出不会包含这些 Ping 特有关键词，不会被展示到页面上。

---

## 修复前后对比

| 测试项 | 漏洞版 | 修复版 |
|:---|:---|:---|
| `ip=127.0.0.1;whoami` | ✅ 返回 `root` | ❌ "无效的 IP 或域名格式" |
| `ip=8.8.8.8\|id` | ✅ 返回 `uid=0` | ❌ 格式校验拦截 |
| `ip=127.0.0.1;cat /etc/passwd` | ✅ 返回文件内容 | ❌ 格式校验拦截 |
| `ip=8.8.8.8` 正常 Ping | ✅ 正常 | ✅ 正常（bytes from, rtt） |
| `ip=127.0.0.1` 回环 Ping | ✅ 正常 | ✅ 正常 |
| `ip=example.com` 域名 Ping | ✅ 正常 | ✅ 正常 |
| `ip=invalid!!!` 非法格式 | 命令报错 | ❌ "无效的 IP 或域名格式" |

## 使用教程

### 正常使用流程

1. 使用 `admin / admin123` 登录系统
2. 点击导航栏的 **Ping测试** 或首页的 **Ping测试** 按钮
3. 输入合法 IP（如 `8.8.8.8`）或域名（如 `example.com`）
4. 点击 **Ping** 按钮查看控制台风格的结果

### 漏洞版测试

```bash
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt
curl -b /tmp/cookies.txt -d "ip=127.0.0.1;whoami" http://127.0.0.1:5000/ping
```

### 修复版验证

```bash
curl -b /tmp/cookies.txt -d "ip=127.0.0.1;whoami" http://127.0.0.1:5000/ping
# 返回：无效的 IP 地址或域名格式

curl -b /tmp/cookies.txt -d "ip=8.8.8.8" http://127.0.0.1:5000/ping
# 返回：64 bytes from 8.8.8.8 ...
```

## 免责声明

本仓库提供的漏洞代码和 POC 测试命令仅用于 **网络安全教学与合法授权测试**。禁止用于未经授权的系统测试或攻击，任何非法使用造成的法律后果由使用者自行承担。请遵守《中华人民共和国网络安全法》及相关法律法规。
