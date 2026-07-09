【安全修复版代码 — app.py 上传路由部分】

import os
import secrets
import uuid
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

# 修复4：头像上传上限从16MB调整为5MB，减少存储耗尽风险
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# ...（登录、注册、搜索路由与修复前一致，此处省略）

# ═══════════════════════════════════════════
# 【修复】头像上传路由 — 三重安全校验
# ═══════════════════════════════════════════
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 修复1：文件扩展名白名单 — 仅允许标准图片格式
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}


def _validate_image_content(filepath):
    """修复2：通过文件魔术头校验是否为真实图片"""
    with open(filepath, "rb") as f:
        header = f.read(12)

    magic_map = {
        b"\xff\xd8\xff": "JPEG",
        b"\x89PNG\r\n\x1a\n": "PNG",
        b"GIF87a": "GIF",
        b"GIF89a": "GIF",
        b"RIFF": "WEBP",  # WebP 文件以 RIFF 开头，第8-11字节应为 WEBP
    }

    for magic, fmt in magic_map.items():
        if header.startswith(magic):
            if fmt == "WEBP" and header[8:12] != b"WEBP":
                continue
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

        # 修复3：使用 UUID 重命名文件，防止同名覆盖 + 防止路径穿越
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
