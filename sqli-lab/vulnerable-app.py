"""vulnerable-app.py — 存在SQL注入漏洞的用户管理系统"""
import os, sqlite3
from flask import Flask, render_template, request, redirect, session

# 确保工作目录为脚本所在目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# ===== 初始化数据库 =====
def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    # 表字段：id, username, password, email, phone
    c.execute("CREATE TABLE IF NOT EXISTS users ("
              "id INTEGER PRIMARY KEY AUTOINCREMENT, "
              "username TEXT UNIQUE, password TEXT, "
              "email TEXT, phone TEXT)")
    c.execute("INSERT OR IGNORE INTO users VALUES "
              "(1, 'admin', 'admin123', 'admin@example.com', '13800138000')")
    c.execute("INSERT OR IGNORE INTO users VALUES "
              "(2, 'alice', 'alice2025', 'alice@example.com', '13900139001')")
    conn.commit()
    conn.close()

# ===== 登录（无CSRF，明文比对）=====
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 直接用==比对密码
        c.execute("SELECT * FROM users WHERE username=?", (u,))
        row = c.fetchone()
        conn.close()
        if row and row[2] == p:    # row[2]是password字段
            session["username"] = u
            return redirect("/")
        return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")

# ===== 首页 =====
@app.route("/")
def index():
    u = session.get("username")
    info = None
    if u:
        info = {"username": u}
    return render_template("index.html", user=info, search_results=None, keyword="")

# ===== 【漏洞】搜索路由 — f-string 拼接 SQL =====
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 漏洞：直接拼接用户输入
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] {sql}")
        c.execute(sql)
        for row in c.fetchall():
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
        conn.close()
    u = session.get("username")
    info = {"username": u} if u else None
    return render_template("index.html", user=info, search_results=results, keyword=keyword)

# ===== 【漏洞】注册路由 — f-string 拼接 SQL =====
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email    = request.form.get("email", "")
        phone    = request.form.get("phone", "")
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 漏洞：直接拼接用户输入
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] {sql}")
        try:
            c.execute(sql)
            conn.commit()
            conn.close()
            return render_template("login.html", message="注册成功，请登录")
        except Exception as e:
            conn.close()
            return render_template("register.html", error="注册失败：" + str(e))
    return render_template("register.html")

# ===== 退出 =====
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ===== 启动 =====
if __name__ == "__main__":
    init_db()
    # 使用 HTTP（非HTTPS）以便 curl 测试
    app.run(debug=True, host="0.0.0.0", port=5000)
