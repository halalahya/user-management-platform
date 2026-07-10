# ═══════════════════════════════════════════
# 【修复】个人中心路由 — 登录校验 + 默认当前用户
# ═══════════════════════════════════════════
@app.route("/profile")
def profile():
    # 修复 VULN-PR-01：要求用户必须登录
    if "username" not in session:
        return redirect("/login")

    user_id = request.args.get("user_id")

    # 修复 VULN-PR-06：未传 user_id 时自动解析当前登录用户
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
    # 修复 VULN-PR-02：要求用户必须登录
    if "username" not in session:
        return redirect("/login")

    # 修复 VULN-PR-05：CSRF Token 校验
    if not validate_csrf_token():
        return render_template("login.html", error="会话已过期，请刷新页面后重试！")

    user_id = request.form.get("user_id")
    amount = request.form.get("amount")

    if not user_id or not amount:
        return "缺少参数", 400

    # 修复 VULN-PR-03 + VULN-PR-04：校验金额格式与范围
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
