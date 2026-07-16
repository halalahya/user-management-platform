# ═══════════════════════════════════════════
# 【修复】Ping 网络诊断路由 — IP白名单 + 禁用shell
# ═══════════════════════════════════════════
@app.route("/ping", methods=["GET", "POST"])
def ping():
    if "username" not in session:
        return redirect("/login")

    result = ""
    if request.method == "POST":
        ip = request.form.get("ip", "")

        # 修复 VULN-PING-01：IP 地址白名单校验
        # 仅允许合法 IP（IPv4）和合法域名
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'

        if not re.match(ip_pattern, ip) and not re.match(domain_pattern, ip):
            result = "无效的 IP 地址或域名格式"
        else:
            # 修复 VULN-PING-01：使用参数列表替代 shell=True
            # 修复 VULN-PING-02：仅返回 ping 统计信息
            try:
                output = subprocess.check_output(
                    ["ping", "-c", "3", ip],
                    timeout=30,
                    stderr=subprocess.STDOUT
                )
                raw = output.decode("utf-8", errors="replace")
                # 提取关键统计信息（丢包率、rtt 等）
                lines = raw.split("\n")
                filtered = [l for l in lines if "statistics" in l or "packet loss" in l or "rtt" in l or "round-trip" in l or "bytes from" in l or "time=" in l]
                result = "\n".join(filtered) if filtered else raw
            except subprocess.CalledProcessError as e:
                raw = e.output.decode("utf-8", errors="replace")
                result = f"Ping 请求失败\n{raw}"
            except subprocess.TimeoutExpired:
                result = "Ping 超时"
            except Exception as e:
                result = f"执行出错: {str(e)}"

    return render_template("ping.html", result=result)
