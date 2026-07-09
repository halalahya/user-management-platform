【漏洞原版代码 — app.py 上传路由部分】

import os
import secrets
import sqlite3
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["SESSION_COOKIE_NAME"] = "session"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 漏洞：体积上限过大

# ...（登录、注册、搜索路由与现有代码一致，此处省略）

# ═══════════════════════════════════════════
# 【漏洞】头像上传路由 — 无任何安全校验
# ═══════════════════════════════════════════
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择一个文件")

        # 漏洞1：未校验文件扩展名 → 允许上传任意类型文件（.php/.py/.exe/.html）
        # 漏洞2：未校验文件内容 → 无法识别是否为真实图片
        # 漏洞3：使用原始文件名 → 同名文件互相覆盖
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        file_url = url_for("static", filename=f"uploads/{filename}")
        return render_template("upload.html", success=True, file_url=file_url, filename=filename)

    return render_template("upload.html")
