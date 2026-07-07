from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# SSL 证书路径
SSL_CERT = "ssl/cert.pem"
SSL_KEY = "ssl/key.pem"

USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


@app.after_request
def add_security_headers(response):
    """为所有响应添加安全头，修复点击挟持、HSTS等问题"""
    # 修复问题4：禁止页面被嵌入 iframe，防止点击挟持攻击
    response.headers["X-Frame-Options"] = "DENY"
    # CSP 中同样限制 frame 嵌套，双重保险
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    # 修复问题2：启用 HSTS，强制浏览器在1年内只能通过 HTTPS 访问
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # 禁用浏览器自动检测 MIME 类型，降低 XSS 风险
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def sanitize_user_info(user_info):
    """构建不含敏感字段（邮箱）的用户信息，修复问题3（电子邮件地址泄露）"""
    if user_info is None:
        return None
    return {
        "username": user_info["username"],
        "password": user_info["password"],
        "phone": user_info["phone"],
        "role": user_info["role"],
        "balance": user_info["balance"]
    }


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = sanitize_user_info(USERS[username])
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username in USERS and USERS[username]["password"] == password:
            session["username"] = username
            user_info = sanitize_user_info(USERS[username])
            return render_template("index.html", user=user_info)
        else:
            return render_template("login.html", error="用户名或密码错误，请重试！")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    # 修复问题1和问题2：使用 SSL/TLS 加密传输，替换原来的明文 HTTP
    # 使用 self-signed 证书，生产环境应替换为受信任 CA 签发的证书
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000,
        ssl_context=(SSL_CERT, SSL_KEY)
    )
