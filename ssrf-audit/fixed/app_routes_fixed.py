import socket

# ═══════════════════════════════════════════
# 【修复】URL 抓取路由 — 协议白名单 + 内网IP拦截 + 端口校验
# ═══════════════════════════════════════════
@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    if "username" not in session:
        return redirect("/login")

    url = request.form.get("url", "")
    if not url:
        return "缺少 url 参数", 400

    # 修复 VULN-SSRF-01：协议白名单，仅允许 http/https
    if not url.startswith("http://") and not url.startswith("https://"):
        return "不支持的协议，仅允许 http:// 和 https://", 400

    # 修复 VULN-SSRF-03：URL 格式校验
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.hostname:
        return "无效的 URL 格式", 400

    # 修复 VULN-SSRF-03：端口范围校验
    port = parsed.port
    if port is not None and (port < 1 or port > 65535):
        return "无效的端口号", 400

    # 修复 VULN-SSRF-02：解析域名并检查是否为内网地址
    try:
        ip = socket.gethostbyname(parsed.hostname)
    except socket.gaierror:
        return "无法解析域名", 400

    # 内网 IP 黑名单校验
    if _is_private_ip(ip):
        return "不允许访问内网地址", 400

    try:
        resp = urllib.request.urlopen(url, timeout=10)
        status_code = resp.getcode()
        raw = resp.read()
        content = raw.decode("utf-8", errors="replace")[:5000]
        result = f"状态码: {status_code}\n\n--- 响应内容（前 5000 字符）---\n\n{content}"
    except Exception as e:
        result = f"抓取出错: {str(e)}"

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = sanitize_user_info(USERS[username])

    return render_template("index.html", user=user_info, fetch_url=url, fetch_result=result)


def _is_private_ip(ip):
    """检查 IP 是否为内网地址"""
    parts = ip.split(".")
    if len(parts) != 4:
        return True

    first = int(parts[0])

    # 127.0.0.0/8 回环地址
    if first == 127:
        return True
    # 10.0.0.0/8 私有 A 类
    if first == 10:
        return True
    # 169.254.0.0/16 链路本地（含云元数据）
    if first == 169 and int(parts[1]) == 254:
        return True
    # 172.16.0.0/12 私有 B 类
    if first == 172 and 16 <= int(parts[1]) <= 31:
        return True
    # 192.168.0.0/16 私有 C 类
    if first == 192 and int(parts[1]) == 168:
        return True
    # 0.0.0.0/8
    if first == 0:
        return True
    # ::1 IPv6 回环
    if ip == "::1":
        return True

    return False
