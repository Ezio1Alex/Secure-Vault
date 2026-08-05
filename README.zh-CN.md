# 🔒 私人密码箱 (Secure Vault)

[![Deploy Worker](https://github.com/Ezio1Alex/Secure-Vault/actions/workflows/deploy.yml/badge.svg)](https://github.com/Ezio1Alex/Secure-Vault/actions/workflows/deploy.yml)

**私人密码箱** 是一个运行在 Cloudflare Workers 上的 **零知识、端到端加密** 密码管理器。所有密码均在浏览器端完成加密和解密，服务端永远无法获取明文信息。

> English version available at [README.md](README.md)

---

## 功能特性 ✨

| 特性 | 说明 |
|---|---|
| 🔒 **零知识架构** | 服务端不存储任何明文密码，数据泄露也无法破解 |
| 🛡️ **AES-GCM 256 位加密** | PBKDF2 密钥派生（60 万次迭代），暴力破解成本极高 |
| 📱 **移动端自适应** | 完美适配手机和桌面端 |
| 🌙 **深色/浅色模式** | 支持系统主题自动跟随和手动切换 |
| 🔑 **强密码生成器** | 内置可自定义的随机密码生成工具 |
| 📌 **置顶功能** | 常用账号置顶，快速定位 |
| 🔍 **搜索与筛选** | 按网站名称、账号名、备注搜索，也可按网站筛选 |
| 📤 **导入/导出备份** | 支持明文 JSON 备份导出与恢复导入 |
| ⏰ **自动锁定** | 闲置 3 分钟自动锁定，保护隐私安全 |
| 🏗️ **按网站分组** | 凭证自动按网站分组展示，可折叠展开 |
| 🌐 **中英双语** | 支持中文/英文切换，自动识别浏览器语言，偏好保存在 localStorage |

---

## 架构设计 🏗️

```
┌──────────────────────────────────────────────────────────────────┐
│  浏览器端 (Web Crypto API)                                       │
│                                                                  │
│  主密码 (Master Password)                                        │
│       │                                                          │
│       ├── PBKDF2(SHA-256, 600k 次迭代) ──► 主密钥 (AES-GCM)      │
│       │                              │                           │
│       └── SHA-256(用户名:密码:salt) ──► 认证密钥                 │
│                                                  │               │
└───────────────────────────────────────────────────│──────────────┘
                                                   │ x-username
                                                   │ x-auth-key
                                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  Cloudflare Workers (Hono 框架)              ┌──────────────────┐│
│  ● 认证中间件 (verify x-auth-key)            │  Cloudflare      ││
│  ● 加密数据的 CRUD 接口                      │  D1 Database     ││
│  ● 首页提供 SPA 页面 (GET /)                 │  (SQLite)        ││
│                                              │                  ││
│                                              │  users           ││
│                                              │  passwords       ││
│                                              │  vault_config    ││
│                                              └──────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

### 安全机制详解

1. **Master Salt** —— 首次请求时自动生成，存储在 `vault_config` 表中
2. **认证密钥 (Auth Key)** —— `SHA-256(用户名 + ":" + 密码 + ":" + salt)`，作为 `x-auth-key` 请求头发送
3. **主密钥 (Master Key)** —— `PBKDF2(密码, salt, 600000 次迭代)` → AES-GCM 256 位密钥。**永远不离开浏览器**
4. **加密数据** —— `{ site, username, password, note }` JSON 序列化 → AES-GCM 加密 → base64 编码 → 存入 D1

> ⚠️ **主密码遗忘 = 数据永久丢失。** 系统没有后门，没有重置密码功能，无法人工恢复——这是设计使然。

---

## 技术栈 🛠️

| 层级 | 技术 |
|---|---|
| 运行环境 | [Cloudflare Workers](https://workers.cloudflare.com/) |
| Web 框架 | [Hono](https://hono.dev/) v4 |
| 数据库 | [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite) |
| 加密方案 | Web Crypto API (AES-GCM 256 / PBKDF2 / SHA-256) |
| 前端 | 纯 HTML + CSS + JavaScript（SPA，无框架依赖） |
| 国际化 | 客户端翻译字典 + `data-i18n` DOM 绑定 + `localStorage` 持久化 |
| 部署工具 | [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) + GitHub Actions |

---

## 快速开始 🚀

从零开始到上线运行 + 自动部署，跟着下面的步骤走就行。

---

### 📋 环境要求

| 需要准备什么 | 怎么获取 |
|---|---|
| [Node.js](https://nodejs.org/) 18+ | 去 nodejs.org 下载安装 |
| [Cloudflare 账号](https://dash.cloudflare.com/sign-up) | 免费注册 |
| Wrangler CLI | `npm install -g wrangler`（全局安装，方便使用） |

---

### 🔧 第一部分：一次性初始化（只需做一次）

#### 1. 克隆项目并安装依赖

```bash
git clone https://github.com/Ezio1Alex/Secure-Vault.git
cd Secure-Vault
npm install
```

#### 2. 登录 Cloudflare

```bash
npx wrangler login
```

浏览器会自动打开授权页面，点击 **Allow** 授权即可。

#### 3. 创建 D1 数据库

```bash
npx wrangler d1 create vault_db
```

你会看到类似这样的输出：
```
✅ Successfully created DB 'vault_db' in region APAC
Created your database using D1's new storage backend.
[[d1_databases]]
binding = "DB"
database_name = "vault_db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**复制 `database_id`**（那串 UUID），下一步要用。

#### 4. 修改 wrangler.toml 配置

打开 [`wrangler.toml`](wrangler.toml)，把 database_id 粘贴进去：

```toml
[[d1_databases]]
binding = "DB"
database_name = "vault_db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # ← 粘贴到这里
```

#### 5. 初始化数据库表

```bash
npx wrangler d1 migrations apply vault_db --remote
```

出现以下内容代表成功：
```
✅ Applied migration 001_create_tables.sql
```

如果有报错，检查 `wrangler.toml` 中的 `database_id` 是否粘贴正确。

#### 6. 本地测试

```bash
npm run dev
# 或：npx wrangler dev
```

浏览器打开 `http://localhost:8787`，应该能看到登录页面。

如果想连真实 D1 数据库做本地测试：
```bash
npx wrangler d1 migrations apply vault_db --local
npx wrangler dev
```

#### 7. 首次部署上线

```bash
npm run deploy
# 或：npx wrangler deploy
```

部署成功后终端会显示你的 Worker 地址，格式如 `https://secure-vault.你的账号.workers.dev`，打开即可使用。

---

### 🤖 第二部分：配置自动部署（每次推送自动部署）

上线之后，配置 GitHub Actions 实现：每次 `git push` 到 `main` 分支，自动部署最新版本。

#### 1. 创建 Cloudflare API Token

- 打开 [Cloudflare 控制台 → 我的资料 → API Tokens](https://dash.cloudflare.com/profile/api-tokens)
- 点击 **Create Token** → 选择 **Edit Cloudflare Workers** 模板
- **权限确认**（确保有以下权限）：

  | 权限 | 访问级别 |
  |---|---|
  | Workers: Edit | Include |
  | Workers Routes: Edit | Include |
  | D1: Edit | Include |
  | Account Settings: Read | Include |

- 点击 **Continue to Summary → Create Token**
- **立即复制 Token**（关闭页面后就看不到了！）

#### 2. 在 GitHub 仓库中添加 Secret

- 打开你的 GitHub 仓库：`https://github.com/Ezio1Alex/Secure-Vault`
- 点击 **Settings → Secrets and variables → Actions**
- 点击 **New repository secret**
  - **Name**: `CLOUDFLARE_API_TOKEN`
  - **Secret**: 粘贴刚才复制的 Token
  - 点击 **Add secret**

#### 3. 推送代码触发自动部署

```bash
git add -A
git commit -m "更新了功能"
git push origin main
```

搞定！去仓库的 **Actions** 标签页就能看到部署进度：

```
✅ Setup Node.js
✅ Install dependencies
✅ Deploy to Cloudflare Workers
```

`.github/workflows/deploy.yml` 这个工作流每次推送只做一件事：部署最新代码。数据库建表在初始化时一次完成，后续无需操心。

如果以后增加新的迁移文件，本地手动跑一下就行：

```bash
npx wrangler d1 migrations apply vault_db --remote
```

---

### 📊 部署流程示意图

```
你推送到 GitHub main
        │
        ▼
GitHub Actions (deploy.yml)
        │
        ├─ npm ci              ← 安装依赖
        └─ wrangler deploy     ← 部署到 Cloudflare Workers
        │
        ▼
你的应用在 *.workers.dev 上运行
```

---

## 数据库设计 📊

```sql
-- 用户表（代码中配置了最大 5 个账号）
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 加密的密码记录
CREATE TABLE passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    encrypted_data TEXT NOT NULL,
    iv TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    pinned INTEGER DEFAULT 0,
    FOREIGN KEY(username) REFERENCES users(username)
);

-- 键值配置表（存储 master salt）
CREATE TABLE vault_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

---

## API 接口 📡

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| `GET` | `/` | 否 | 提供 SPA 页面 |
| `GET` | `/api/salt` | 否 | 获取或生成 Master Salt |
| `POST` | `/api/register` | 否 | 注册新账号 |
| `POST` | `/api/login` | 否 | 登录认证 |
| `GET` | `/api/secrets` | 是 | 获取所有加密记录 |
| `POST` | `/api/secrets` | 是 | 创建新加密记录 |
| `PUT` | `/api/secrets/:id` | 是 | 更新已有记录 |
| `DELETE` | `/api/secrets/:id` | 是 | 删除记录 |
| `POST` | `/api/secrets/:id/pin` | 是 | 切换置顶状态 |

> 需要认证的接口需要在请求头中携带 `x-username` 和 `x-auth-key`（客户端派生）。

---

## 项目结构 📁

```
secure-vault/
├── src/
│   └── index.ts          # 主程序（API + SPA 页面全部在此文件）
├── migrations/
│   └── 001_create_tables.sql
├── schema.sql            # 数据库完整结构（参考用）
├── wrangler.toml         # Cloudflare Workers 配置文件
├── package.json
├── README.md             # 说明文档（英文）
├── README.zh-CN.md       # 说明文档（中文）
└── LICENSE
```

整个应用——后端 API 路由、认证中间件、数据库查询、以及完整的前端 SPA（HTML/CSS/JS）——都包含在 **一个文件** [`src/index.ts`](src/index.ts) 中。这种设计让部署变得异常简单。

---

## 环境变量 🌐

所有配置均在 [`wrangler.toml`](wrangler.toml) 中。D1 数据库绑定 `DB` 是唯一的必需绑定。

代码中不包含任何硬编码的密钥或 API Token。使用 GitHub Actions 部署时，需要在仓库 Secrets 中设置 `CLOUDFLARE_API_TOKEN`。

---

## 自定义配置 🎨

- **用户数量上限**：修改 `src/index.ts` 中第 32 行的 `userCount.count >= 5` 数值
- **密码强度规则**：调整 SPA JavaScript 中的 `evaluatePasswordStrength()` 函数
- **自动锁定时间**：修改 SPA JavaScript 中的 `WARNING_MS`（150000）和 `LOCK_MS`（180000）
- **PBKDF2 迭代次数**：修改 `deriveKey()` 中的 `600000`——越高越安全，但客户端计算越慢
- **语言切换**：在登录页或主界面右上角点击 **EN/中** 按钮即可切换中英文，偏好自动保存在浏览器 `localStorage` 中

---

## License 许可证 📄

[MIT](LICENSE)

---

## 免责声明 ⚠️

本项目按现状提供，仅供教育和个人使用。虽然采用了客户端加密的最佳实践，但在用于存储真实敏感数据之前，请务必审查代码并理解安全模型。作者不对因使用本软件导致的任何数据丢失或安全漏洞承担责任。
