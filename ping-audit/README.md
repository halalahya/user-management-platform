# Ping 网络诊断功能模块 — 安全审计与修复

## 项目整体介绍

本项目基于 Flask + SQLite3 开发，提供用户登录、注册、搜索、头像上传、个人中心、充值、动态页面加载、URL 抓取等功能。本次新增了 **Ping 网络诊断功能**，允许已登录用户对指定的 IP 或域名执行 Ping 操作，用于网络连通性测试。

初始版本存在命令注入漏洞，攻击者可利用 shell 拼接执行任意系统命令。本模块对该功能进行专项安全审计，共发现 2 项典型安全漏洞，并逐一实施修复。

## Ping 功能设计说明

| 项目 | 说明 |
|------|------|
| 路由 | `GET /ping` 显示页面、`POST /ping` 执行 Ping |
| 前端 | 黑色背景绿色文字控制台风格输出区域 |
| 参数 | `ip` — IP 地址或域名 |
| 后端命令 | `ping -c 3 {ip}` （漏洞版）；`["ping", "-c", "3", ip]` （修复版） |

## Ping 模块漏洞汇总报告

### VULN-PING-01：命令注入（高危）

| 项目 | 内容 |
|------|------|
| **风险等级** | ⛔ 高危 — CVSS 9.8 |
| **漏洞成因** | `f"ping -c 3 {ip}"` 字符串拼接 + `shell=True`，攻击者可在 ip 中注入 `;id`、`\|whoami` 等 shell 命令 |
| **漏洞代码** | `cmd = f"ping -c 3 {ip}"` + `subprocess.check_output(cmd, shell=True)` |
| **利用 Payload** | `127.0.0.1;whoami`、`8.8.8.8;cat /etc/passwd`、`127.0.0.1\|id` |
| **危害说明** | 攻击者可执行任意系统命令，读取文件、创建后门、完全控制服务器 |

### VULN-PING-02：执行结果直接回显（中危）

| 项目 | 内容 |
|------|------|
| **风险等级** | ⚠️ 中危 — CVSS 5.3 |
| **漏洞成因** | 命令执行结果未经过滤直接渲染到页面，配合命令注入可放大攻击效果 |
| **漏洞代码** | `result = output.decode("utf-8", errors="replace")` |
| **危害说明** | 注入命令的输出结果被格式化展示，便于攻击者读取敏感信息 |

## 漏洞逐一修复方案

### 修复 VULN-PING-01：命令注入

**修复方式：** IP 地址白名单正则校验 + 禁用 shell=True + 使用参数列表。

**修复后代码：**
```python
# IP 地址格式校验（IPv4）
ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
# 域名格式校验
domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'

if not re.match(ip_pattern, ip) and not re.match(domain_pattern, ip):
    result = "无效的 IP 地址或域名格式"
else:
    # 使用参数列表，禁用 shell=True
    output = subprocess.check_output(["ping", "-c", "3", ip], timeout=30)
```

**修复原理：** `re.match()` 对 ip 参数进行白名单格式校验。`;`、`|`、`&`、`` ` `` 等 shell 特殊字符无法通过校验。同时将 `shell=True` 改为参数列表形式，系统将 ip 作为 ping 命令的一个普通参数传递，不会解析其中的 shell 语法。

### 修复 VULN-PING-02：执行结果过滤

**修复方式：** 仅提取 Ping 命令的标准输出行（包含 `bytes from`、`statistics`、`rtt`、`packet loss` 等关键信息），过滤掉注入命令的输出。

**修复后代码：**
```python
raw = output.decode("utf-8", errors="replace")
lines = raw.split("\n")
filtered = [l for l in lines if "statistics" in l or "packet loss" in l or "rtt" in l or "bytes from" in l or "time=" in l]
result = "\n".join(filtered) if filtered else raw
```

## 部署启动方式

```bash
# 安装依赖
pip install flask

# 克隆项目后进入 Ping 审计目录
cd ping-audit

# 启动漏洞版
cd vulnerable && python app.py

# 启动修复版
cd fixed && python app.py

# 访问地址
https://127.0.0.1:5000

# 默认账号
admin / admin123
```

## 访问使用教程

### 正常使用流程

1. 使用 `admin / admin123` 登录系统
2. 点击导航栏的 **Ping测试** 或首页的 **Ping测试** 按钮
3. 输入合法 IP（如 `8.8.8.8`）或域名（如 `example.com`）
4. 点击 **Ping** 按钮查看结果

### 漏洞版测试（命令注入）

```bash
# 登录
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt

# 正常 Ping
curl -b /tmp/cookies.txt -d "ip=8.8.8.8" http://127.0.0.1:5000/ping

# 命令注入（漏洞版可执行，修复版拦截）
curl -b /tmp/cookies.txt -d "ip=127.0.0.1;whoami" http://127.0.0.1:5000/ping
```

### 修复版验证

```bash
# 格式校验拦截
curl -b /tmp/cookies.txt -d "ip=127.0.0.1;whoami" http://127.0.0.1:5000/ping
# 返回：无效的 IP 地址或域名格式

# 正常功能不受影响
curl -b /tmp/cookies.txt -d "ip=8.8.8.8" http://127.0.0.1:5000/ping
# 返回：64 bytes from 8.8.8.8 ...
```

## 目录结构

```
ping-audit/
├── 1-SECURITY_AUDIT.md        # 安全审计报告
├── vulnerable/                 # 漏洞原版代码
│   ├── app.py
│   ├── ping.html
│   ├── base.html
│   └── index.html
├── fixed/                     # 修复版代码
│   ├── app.py
│   ├── app_route_fixed.py     # 修复后的路由代码片段
│   ├── ping.html
│   ├── base.html
│   └── index.html
└── README.md                  # 本文件
```
