import os
import secrets
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ═══════════════════════════════════════════
# Flask 会话安全加固
# ═══════════════════════════════════════════

# 从环境变量读取 secret_key，不存在则生成 64 位随机密钥（修复 #3）
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    secrets.token_hex(32)
)

# Session Cookie 安全配置（修复 #7：Secure + HttpOnly + SameSite + 过期时间）
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["SESSION_COOKIE_NAME"] = "session"


# ═══════════════════════════════════════════
# 用户数据库 — 密码从环境变量读取（修复 #1）
# ═══════════════════════════════════════════
# 不再在代码中出现任何形式的密码字符串（即使是传给 hash 函数的参数）
# 管理员通过设置环境变量 ADMIN_PASSWORD / ALICE_PASSWORD 来指定密码
# 如果环境变量未设置，则在启动时生成随机密码并打印到控制台

_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
_ALICE_PASSWORD = os.environ.get("ALICE_PASSWORD")

if not _ADMIN_PASSWORD:
    _ADMIN_PASSWORD = secrets.token_hex(16)
    print(f"[!] 环境变量 ADMIN_PASSWORD 未设置，本次使用随机密码: {_ADMIN_PASSWORD}")
    print("    建议设置环境变量以使用固定密码：export ADMIN_PASSWORD='your-strong-password'")

if not _ALICE_PASSWORD:
    _ALICE_PASSWORD = secrets.token_hex(16)
    print(f"[!] 环境变量 ALICE_PASSWORD 未设置，本次使用随机密码: {_ALICE_PASSWORD}")
    print("    建议设置环境变量以使用固定密码：export ALICE_PASSWORD='your-strong-password'")

USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash(_ADMIN_PASSWORD),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash(_ALICE_PASSWORD),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


# ═══════════════════════════════════════════
# 暴力破解防护
# ═══════════════════════════════════════════
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15


# ═══════════════════════════════════════════
# 安全响应头（修复 #8 #9 #10 #11）
# ═══════════════════════════════════════════
@app.after_request
def add_security_headers(response):
    """为所有 HTTP 响应添加安全头"""
    # 点击挟持防护
    response.headers["X-Frame-Options"] = "DENY"
    # 完整内容安全策略
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "frame-ancestors 'none'"
    )
    # HSTS：强制 1 年内仅 HTTPS
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    # 禁止 MIME 嗅探
    response.headers["X-Content-Type-Options"] = "nosniff"
    # 限制 referrer 泄露
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ═══════════════════════════════════════════
# CSRF Token 机制（修复 #6）
# ═══════════════════════════════════════════
def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

app.jinja_env.globals["csrf_token"] = generate_csrf_token


def validate_csrf_token():
    token = session.pop("_csrf_token", None)
    submitted = request.form.get("_csrf_token")
    if not token or not submitted:
        return False
    return secrets.compare_digest(token, submitted)


# ═══════════════════════════════════════════
# 工具函数（修复 #4 #14）
# ═══════════════════════════════════════════
def sanitize_user_info(user_info):
    """构建不含敏感字段的用户信息，过滤密码和邮箱"""
    if user_info is None:
        return None
    return {
        "username": user_info["username"],
        "phone": user_info["phone"],
        "role": user_info["role"],
        "balance": user_info["balance"]
    }


# ═══════════════════════════════════════════
# 首页路由
# ═══════════════════════════════════════════
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = sanitize_user_info(USERS[username])
    return render_template("index.html", user=user_info)


# ═══════════════════════════════════════════
# 登录路由
# ═══════════════════════════════════════════
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"

        # 暴力破解检测（修复 #15）
        if client_ip in LOGIN_ATTEMPTS:
            attempts, lockout_time = LOGIN_ATTEMPTS[client_ip]
            if attempts >= MAX_LOGIN_ATTEMPTS:
                from datetime import datetime, timezone
                if datetime.now(timezone.utc) < lockout_time:
                    remaining = int(
                        (lockout_time - datetime.now(timezone.utc)).total_seconds() / 60
                    )
                    return render_template(
                        "login.html",
                        error=f"登录尝试过于频繁，请 {remaining} 分钟后再试！"
                    )
                else:
                    del LOGIN_ATTEMPTS[client_ip]

        # CSRF 验证（修复 #6）
        if not validate_csrf_token():
            return render_template("login.html", error="会话已过期，请刷新页面后重试！")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 输入校验（修复 #13）
        if not username or not password:
            return render_template("login.html", error="用户名和密码不能为空！")
        if len(username) > 50 or len(password) > 128:
            return render_template("login.html", error="输入内容过长！")

        # 身份验证（修复 #1：安全哈希比对）
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            LOGIN_ATTEMPTS.pop(client_ip, None)
            session.permanent = True
            session["username"] = username
            user_info = sanitize_user_info(USERS[username])
            return render_template("index.html", user=user_info)
        else:
            # 记录失败
            from datetime import datetime, timezone, timedelta as td
            if client_ip not in LOGIN_ATTEMPTS:
                LOGIN_ATTEMPTS[client_ip] = [
                    1,
                    datetime.now(timezone.utc) + td(minutes=LOGIN_LOCKOUT_MINUTES)
                ]
            else:
                count, lock_until = LOGIN_ATTEMPTS[client_ip]
                LOGIN_ATTEMPTS[client_ip] = [count + 1, lock_until]

            return render_template("login.html", error="用户名或密码错误，请重试！")

    return render_template("login.html")


# ═══════════════════════════════════════════
# 退出路由
# ═══════════════════════════════════════════
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ═══════════════════════════════════════════
# 启动入口
# ═══════════════════════════════════════════
if __name__ == "__main__":
    SSL_CERT = "ssl/cert.pem"
    SSL_KEY = "ssl/key.pem"

    # 首次启动自动生成自签名 SSL 证书
    if not os.path.exists(SSL_CERT) or not os.path.exists(SSL_KEY):
        os.makedirs("ssl", exist_ok=True)
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt

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
            .not_valid_before(dt.datetime.now(dt.timezone.utc))
            .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False
            )
            .sign(key, hashes.SHA256())
        )
        with open(SSL_KEY, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                )
            )
        with open(SSL_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("=" * 56)
    print("  用户管理系统已启动（安全加固版）")
    print(f"  访问地址：https://127.0.0.1:{os.environ.get('PORT', 5000)}")
    print("  关闭 debug 模式 | 强制 HTTPS | 15 项安全加固已生效")
    print("=" * 56)
    app.run(
        debug=False,
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        ssl_context=(SSL_CERT, SSL_KEY)
    )
