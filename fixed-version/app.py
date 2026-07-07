import os
import secrets
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect, session, url_for
)

app = Flask(__name__)

# ──────────── Flask 会话安全加固 ────────────
# 从环境变量读取 secret_key，如果不存在则生成一个随机密钥
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    secrets.token_hex(32)  # 64字符随机十六进制串
)

# Session Cookie 安全配置 —— 修复 #8 #9 #10 #11
app.config["SESSION_COOKIE_HTTPONLY"] = True       # 禁止 JS 读取 cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"      # 限制跨站发送
app.config["SESSION_COOKIE_SECURE"] = True          # 仅 HTTPS 传输
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)  # 2 小时过期
app.config["SESSION_COOKIE_NAME"] = "session"

# ──────────── 用户数据库（密码使用 werkzeug 哈希存储）────────────
# 在代码初始化时一次性生成哈希，运行时不再有明文密码
from werkzeug.security import generate_password_hash, check_password_hash

USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("Admin@2025#Secure"),  # 修复 #1 #21 #22
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("Alice@2025#Secure"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

# ──────────── 暴力破解防护 ────────────
# 记录每个 IP 的登录失败次数 —— 修复 #20
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15


# ──────────── 安全响应头 ────────────
@app.after_request
def add_security_headers(response):
    """为所有响应添加安全头"""
    response.headers["X-Frame-Options"] = "DENY"                              # 修复 #12：禁止 iframe
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"    # 修复 #14：CSP 防嵌套
    response.headers["Strict-Transport-Security"] = (                         # 修复 #13：HSTS
        "max-age=31536000; includeSubDomains"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"                    # 修复 #15
    response.headers["X-XSS-Protection"] = "1; mode=block"                    # XSS 过滤器
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"   # 防 referrer 泄露
    return response


# ──────────── CRSF Token 生成 & 验证 ────────────
def generate_csrf_token():
    """生成并存储 CSRF token 到 session 中 —— 修复 #7"""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf_token


def validate_csrf_token():
    """验证 POST 请求携带的 CSRF token"""
    token = session.pop("_csrf_token", None)
    submitted = request.form.get("_csrf_token")
    if not token or not submitted:
        return False
    return secrets.compare_digest(token, submitted)


# ──────────── 工具函数 ────────────
def sanitize_user_info(user_info):
    """构建不含敏感字段的用户信息，修复 #4 #19（密码明文回显、邮箱泄露）"""
    if user_info is None:
        return None
    return {
        "username": user_info["username"],
        "phone": user_info["phone"],
        "role": user_info["role"],
        "balance": user_info["balance"]
    }


# ──────────── 首页路由 ────────────
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = sanitize_user_info(USERS[username])
    return render_template("index.html", user=user_info)


# ──────────── 登录路由 ────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # 获取客户端 IP
        client_ip = request.remote_addr or "unknown"

        # 暴力破解防护：检查是否被锁定 —— 修复 #20
        if client_ip in LOGIN_ATTEMPTS:
            attempts, lockout_time = LOGIN_ATTEMPTS[client_ip]
            if attempts >= MAX_LOGIN_ATTEMPTS:
                from datetime import datetime, timezone
                if datetime.now(timezone.utc) < lockout_time:
                    remaining = int((lockout_time - datetime.now(timezone.utc)).total_seconds() / 60)
                    return render_template(
                        "login.html",
                        error=f"登录尝试过于频繁，请 {remaining} 分钟后再试！"
                    )
                else:
                    # 锁定时间已过，重置计数
                    del LOGIN_ATTEMPTS[client_ip]

        # CSRF Token 验证 —— 修复 #7
        if not validate_csrf_token():
            return render_template("login.html", error="会话已过期，请刷新页面后重试！")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 输入校验 —— 修复 #18
        if not username or not password:
            return render_template("login.html", error="用户名和密码不能为空！")

        if len(username) > 50 or len(password) > 128:
            return render_template("login.html", error="输入内容过长！")

        # 验证用户身份（使用安全的哈希比对代替明文 == 比对）—— 修复 #1
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            # 登录成功：清除此 IP 的失败记录
            LOGIN_ATTEMPTS.pop(client_ip, None)
            # 启用会话持久化
            session.permanent = True
            session["username"] = username
            user_info = sanitize_user_info(USERS[username])
            return render_template("index.html", user=user_info)
        else:
            # 记录登录失败 —— 修复 #20
            from datetime import datetime, timezone, timedelta as td
            if client_ip not in LOGIN_ATTEMPTS:
                LOGIN_ATTEMPTS[client_ip] = [1, datetime.now(timezone.utc) + td(minutes=LOGIN_LOCKOUT_MINUTES)]
            else:
                count, lock_until = LOGIN_ATTEMPTS[client_ip]
                LOGIN_ATTEMPTS[client_ip] = [count + 1, lock_until]

            return render_template("login.html", error="用户名或密码错误，请重试！")

    return render_template("login.html")


# ──────────── 退出路由 ────────────
@app.route("/logout")
def logout():
    session.clear()       # 清除所有 session 数据
    return redirect("/")


# ──────────── 启动入口 ────────────
if __name__ == "__main__":
    # SSL 证书路径
    SSL_CERT = "ssl/cert.pem"
    SSL_KEY = "ssl/key.pem"

    # 首次启动时自动生成自签名 SSL 证书（如果不存在）
    if not os.path.exists(SSL_CERT) or not os.path.exists(SSL_KEY):
        os.makedirs("ssl", exist_ok=True)
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(SSL_KEY, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        with open(SSL_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    # 修复 #6 #16 #17：启用 HTTPS，关闭 debug 模式，仅监听本地
    # （部署时建议绑定 127.0.0.1 并通过 nginx 反向代理）
    print("=" * 50)
    print("  用户管理系统已启动")
    print(f"  访问地址：https://127.0.0.1:{os.environ.get('PORT', 5000)}")
    print("  关闭 debug 模式 | 强制 HTTPS | 会话安全已加固")
    print("=" * 50)
    app.run(
        debug=False,
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        ssl_context=(SSL_CERT, SSL_KEY)
    )
