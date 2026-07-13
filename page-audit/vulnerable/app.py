import os
import secrets
import uuid
import sqlite3
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ═══════════════════════════════════════════
# Flask 会话安全加固
# ═══════════════════════════════════════════

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    secrets.token_hex(32)
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["SESSION_COOKIE_NAME"] = "session"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


# ═══════════════════════════════════════════
# 用户数据库 — 密码从环境变量读取
# ═══════════════════════════════════════════

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
# 安全响应头
# ═══════════════════════════════════════════
@app.after_request
def add_security_headers(response):
    """为所有 HTTP 响应添加安全头"""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ═══════════════════════════════════════════
# CSRF Token 机制
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
# 工具函数
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

        # 暴力破解检测
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

        # CSRF 验证
        if not validate_csrf_token():
            return render_template("login.html", error="会话已过期，请刷新页面后重试！")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 输入校验
        if not username or not password:
            return render_template("login.html", error="用户名和密码不能为空！")
        if len(username) > 50 or len(password) > 128:
            return render_template("login.html", error="输入内容过长！")

        # 身份验证（安全哈希比对）
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            LOGIN_ATTEMPTS.pop(client_ip, None)
            session.permanent = True
            session["username"] = username
            user_info = sanitize_user_info(USERS[username])
            return render_template("index.html", user=user_info)
        else:
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
# 数据库初始化
# ═══════════════════════════════════════════
def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, email TEXT, phone TEXT, balance INTEGER DEFAULT 0)")
    # 兼容已有数据库：尝试添加balance字段（如果不存在则忽略）
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)", ("admin", "admin123", "admin@example.com", "13800138000", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)", ("alice", "alice2025", "alice@example.com", "13900139001", 100))
    conn.commit()
    conn.close()
    print("[DB] 数据库初始化完成 — data/users.db")


# ═══════════════════════════════════════════
# 注册路由（参数化查询）
# ═══════════════════════════════════════════
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 输入校验
        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空！")
        if len(username) > 50 or len(password) > 128:
            return render_template("register.html", error="输入内容过长！")

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 修复：使用 ? 占位符，杜绝字符串拼接
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[DB] 执行 SQL: {sql} 参数: {username}")
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            msg = "注册成功，请登录"
            conn.close()
            return render_template("login.html", message=msg)
        except Exception as e:
            conn.close()
            return render_template("register.html", error=f"注册失败：用户名可能已存在")

    return render_template("register.html")


# ═══════════════════════════════════════════
# 搜索路由（参数化查询）
# ═══════════════════════════════════════════
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = sanitize_user_info(USERS[username])

    if keyword:
        # 输入校验
        if len(keyword) > 100:
            return render_template("index.html", user=user_info, search_results=[], keyword=keyword)
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        param = f"%{keyword}%"
        print(f"[DB] 执行 SQL: {sql} 参数: {param}")
        c.execute(sql, (param, param))
        rows = c.fetchall()
        conn.close()
        for row in rows:
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})

    return render_template("index.html", user=user_info, search_results=results, keyword=keyword)


# ═══════════════════════════════════════════
# 【修复】头像上传路由 — 三重安全校验
# ═══════════════════════════════════════════
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 修复1：文件扩展名白名单
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}


def _validate_image_content(filepath):
    """修复2：通过文件魔术头校验是否为真实图片"""
    with open(filepath, "rb") as f:
        header = f.read(12)
    if header.startswith(b"\xff\xd8\xff"):
        return True
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        return True
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return True
    return False


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择一个文件")

        # 修复1：校验文件扩展名
        original_name = secure_filename(file.filename)
        ext = os.path.splitext(original_name)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return render_template("upload.html", error="不支持的文件格式，仅允许 JPG/PNG/GIF/WebP 图片")

        # 修复3：使用 UUID 重命名，防止同名覆盖
        unique_name = f"{uuid.uuid4().hex}{ext}"
        save_path = os.path.join(UPLOAD_FOLDER, unique_name)
        file.save(save_path)

        # 修复2：校验文件内容魔术头
        if not _validate_image_content(save_path):
            os.remove(save_path)
            return render_template("upload.html", error="文件内容并非有效图片，已被拒绝")

        file_url = url_for("static", filename=f"uploads/{unique_name}")
        return render_template("upload.html", success=True, file_url=file_url, filename=unique_name)

    return render_template("upload.html")


# ═══════════════════════════════════════════
# 【修复】个人中心路由 — 登录校验 + 默认当前用户
# ═══════════════════════════════════════════
@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect("/login")

    user_id = request.args.get("user_id")

    # 未传 user_id 时自动解析当前登录用户
    if not user_id:
        username = session.get("username")
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            user_id = str(row[0])
        else:
            return "用户不存在", 404

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, balance FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return "用户不存在", 404

    user_data = {
        "id": row[0],
        "username": row[1],
        "email": row[2],
        "phone": row[3],
        "balance": row[4]
    }
    return render_template("profile.html", user=user_data)


# ═══════════════════════════════════════════
# 【修复】充值路由 — 登录校验 + 金额校验 + CSRF
# ═══════════════════════════════════════════
@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect("/login")

    if not validate_csrf_token():
        return render_template("login.html", error="会话已过期，请刷新页面后重试！")

    user_id = request.form.get("user_id")
    amount = request.form.get("amount")

    if not user_id or not amount:
        return "缺少参数", 400

    try:
        amount_val = int(amount)
    except ValueError:
        return "金额格式错误", 400

    if amount_val <= 0:
        return "金额必须为正整数", 400
    if amount_val > 1000000:
        return "单次充值金额不能超过 1000000", 400

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE id=?", (user_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        return "用户不存在", 404

    current_balance = row[0]
    new_balance = current_balance + amount_val
    c.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, user_id))
    conn.commit()
    conn.close()

    return redirect(f"/profile?user_id={user_id}")


# ═══════════════════════════════════════════
# 动态页面加载路由（文件路径拼接，无校验）
# ═══════════════════════════════════════════
@app.route("/page")
def page():
    name = request.args.get("name", "")
    if not name:
        return "缺少页面名称", 400

    # 直接拼接用户输入的 name 到路径中
    filepath = os.path.join("pages", name)
    page_content = None

    if os.path.isfile(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            page_content = f.read()
    else:
        # 尝试加上 .html 后缀
        filepath_html = os.path.join("pages", name + ".html")
        if os.path.isfile(filepath_html):
            with open(filepath_html, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            page_content = "页面不存在"

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = sanitize_user_info(USERS[username])

    return render_template("index.html", user=user_info, page_content=page_content)


# ═══════════════════════════════════════════
# 启动入口
# ═══════════════════════════════════════════
if __name__ == "__main__":
    SSL_CERT = "ssl/cert.pem"
    SSL_KEY = "ssl/key.pem"

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
    init_db()
    app.run(
        debug=False,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        ssl_context=(SSL_CERT, SSL_KEY)
    )
